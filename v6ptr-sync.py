#!/usr/bin/env python3
"""
v6ptr-sync.py — populate GUA reverse (PTR) records in internal BIND by
borrowing hostnames from the dual-stacked IPv4 side.

Mechanism:
  1. Read the IPv6 neighbour cache (NDP) and IPv4 ARP table via `ip neigh`.
  2. Inner-join on MAC (the device-identity anchor that survives RFC 8981
     privacy temporaries: one MAC, many rotating v6 addresses).
  3. For each GUA whose MAC has an IPv4 entry, reverse-resolve the v4 address
     to a hostname (system resolver -> internal BIND).
  4. Reconcile against a JSON desired-state file and emit an nsupdate/TSIG
     transaction: add/overwrite present devices, lazily reap long-gone ones.

Reverse-only by design. Anything needing a forward record has a static
address and is managed elsewhere. Skips link-local always; GUA by default,
ULA optional. No forward (AAAA) records are created.

Dry-run is the DEFAULT: it prints the exact nsupdate transaction and writes
nothing. Pass --apply to actually push and commit state.

Stdlib only (json, subprocess, shutil, ipaddress, socket, argparse, ...).
No sqlite3 dependency, no dig dependency (unless resolver=dig in config).
"""

import argparse
import configparser
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# --- scope networks -------------------------------------------------------
# 2000::/3 is global unicast. fc00::/7 is ULA. fe80::/10 (link-local) is in
# neither, so it is excluded automatically by the scope test.
NET_GUA = ipaddress.ip_network("2000::/3")
NET_ULA = ipaddress.ip_network("fc00::/7")

# NUD states we trust to carry a usable lladdr. FAILED/INCOMPLETE/NONE
# typically have no MAC and are skipped.
USABLE_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}

# Provenance marker. A record is "ours" iff a TXT at the PTR name equals
# f"{MARKER_SENTINEL}:{marker_id}" — the sentinel is human-readable ("what
# wrote this"), the per-install random id is the discriminator ("this exact
# install"). Bumping the trailing digit is a format-version change.
MARKER_SENTINEL = "v6ptr-sync1"

# Bumped when behaviour changes meaningfully; shown in the dry-run debug header.
VERSION = "1.0"

# Explicit candidate dirs, searched after shutil.which(), because a cron/
# scheduler PATH on Gaia rarely matches the interactive expert shell.
BIN_CANDIDATES = ("/bin", "/sbin", "/usr/bin", "/usr/sbin",
                  "/usr/local/bin", "/usr/local/sbin")


# --- binary + config resolution ------------------------------------------
def resolve_binary(name):
    """Resolve a binary by PATH first, then an explicit candidate list.
    Fail loudly rather than trusting an inherited PATH."""
    hit = shutil.which(name)
    if hit:
        return hit
    for d in BIN_CANDIDATES:
        p = os.path.join(d, name)
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    raise FileNotFoundError(
        f"required binary '{name}' not found on PATH or in {BIN_CANDIDATES}")


def load_config(path):
    cp = configparser.ConfigParser()
    if not cp.read(path):
        sys.exit(f"config file not readable: {path}")
    c = {
        "server":     cp.get("dns", "server", fallback="127.0.0.1"),
        "port":       cp.getint("dns", "port", fallback=53),
        "keyfile":    cp.get("dns", "keyfile", fallback="").strip(),
        "key_name":   cp.get("dns", "key_name", fallback="").strip(),
        "key_algorithm": cp.get("dns", "key_algorithm",
                               fallback="hmac-sha256").strip(),
        "key_secret": cp.get("dns", "key_secret", fallback="").strip(),
        "zone":       cp.get("dns", "zone", fallback="").strip(),
        "ttl":        cp.getint("dns", "ttl", fallback=300),
        "interfaces": [s.strip() for s in
                       cp.get("correlation", "interfaces", fallback="").split(",")
                       if s.strip()],
        "scopes":     [s.strip().lower() for s in
                       cp.get("correlation", "scopes", fallback="gua").split(",")
                       if s.strip()],
        "resolver":   cp.get("correlation", "resolver", fallback="system").lower(),
        "only_domain": cp.get("correlation", "only_domain", fallback="").strip().lower(),
        "exclude":    [s.strip() for s in
                       cp.get("correlation", "exclude", fallback="").split(",")
                       if s.strip()],
        "grace_days": cp.getfloat("correlation", "grace_days", fallback=14.0),
        "state_path": cp.get("state", "path",
                             fallback="/var/opt/v6ptr/state.json"),
        "marker_enabled": cp.getboolean("marker", "enabled", fallback=False),
        "marker_id":  cp.get("marker", "id", fallback="").strip(),
    }
    if c["marker_enabled"]:
        if not c["marker_id"]:
            sys.exit("marker enabled but [marker] id is empty. Generate one "
                     "with:  python3 v6ptr-sync.py --gen-marker-id  "
                     "then put it in the config.")
        c["marker_string"] = f"{MARKER_SENTINEL}:{c['marker_id']}"
    else:
        c["marker_string"] = None
    return c


# --- ip neigh parsing (plain text; this iproute2 has no -j) ---------------
def run_ip_neigh(ip_bin, family):
    """family: '-6' for NDP cache, '' for IPv4 ARP."""
    args = [ip_bin]
    if family:
        args.append(family)
    args += ["neigh", "show"]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"{' '.join(args)} failed (rc={r.returncode}): {r.stderr.strip()}")
    return r.stdout


def parse_neigh(text):
    """Parse `ip neigh show` output. Pure function -> unit-testable.

    Line grammar (v4 and v6 share it):
        <addr> dev <iface> [lladdr <mac>] [router] [proxy] <NUD_STATE>
    Some entries (INCOMPLETE/FAILED) omit lladdr. State is the trailing
    uppercase token. Returns list of dicts: {addr, dev, mac, state}.
    """
    out = []
    for line in text.splitlines():
        toks = line.split()
        if not toks:
            continue
        addr = toks[0]
        dev = mac = state = None
        i = 1
        while i < len(toks):
            t = toks[i]
            if t == "dev" and i + 1 < len(toks):
                dev = toks[i + 1]; i += 2; continue
            if t == "lladdr" and i + 1 < len(toks):
                mac = toks[i + 1].lower(); i += 2; continue
            if t in ("router", "proxy", "extern_learn", "offload"):
                i += 1; continue
            # anything left that is an uppercase word is the NUD state
            if t.isupper():
                state = t
            i += 1
        out.append({"addr": addr, "dev": dev, "mac": mac, "state": state})
    return out


# --- correlation ----------------------------------------------------------
def in_scope(addr_obj, scopes):
    if addr_obj in NET_GUA and "gua" in scopes:
        return True
    if addr_obj in NET_ULA and "ula" in scopes:
        return True
    return False


def build_excludes(entries):
    """Parse exclude entries (single addresses or CIDR prefixes) into a list
    of IPv6Network objects. A bare address becomes a /128."""
    nets = []
    for e in entries:
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            sys.exit(f"invalid exclude entry in config: {e!r}")
    return nets


def is_excluded(addr_obj, exclude_nets):
    return any(addr_obj in n for n in exclude_nets
              if n.version == addr_obj.version)


def build_arp_map(v4_entries):
    """mac -> ipv4 string. Prefer entries that carry a MAC and a usable
    state. First usable wins; a later FAILED never overwrites a good one."""
    m = {}
    for e in v4_entries:
        if not e["mac"] or e["state"] not in USABLE_STATES:
            continue
        m.setdefault(e["mac"], e["addr"])
    return m


def reverse_resolve_system(ipv4):
    try:
        return socket.gethostbyaddr(ipv4)[0]
    except (socket.herror, socket.gaierror):
        return None


def reverse_resolve_dig(ipv4, dig_bin):
    r = subprocess.run([dig_bin, "+short", "-x", ipv4],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    name = r.stdout.strip().splitlines()
    return name[0].rstrip(".") if name else None


def correlate(v6_entries, arp_map, cfg, resolver):
    """Return (observed, unmapped).

    observed: {gua_str: {'name': fqdn_no_dot, 'mac': mac, 'v4': ipv4}}
              One MAC may yield many GUAs; all borrow the same v4-derived name.
    unmapped: list of {gua, mac, dev, reason} for in-scope GUAs the tool saw
              but could not turn into a record — purely diagnostic, used only
              by the dry-run debug output.
    """
    observed, unmapped = {}, []
    exclude_nets = cfg.get("exclude_nets", [])
    cache = {}  # ipv4 -> name, avoid repeat lookups for multi-addr devices
    for e in v6_entries:
        if not e["mac"] or e["state"] not in USABLE_STATES:
            continue  # no lladdr / unusable NUD state — not an addressable host
        if cfg["interfaces"] and e["dev"] not in cfg["interfaces"]:
            continue  # off a non-managed interface
        try:
            a = ipaddress.ip_address(e["addr"])
        except ValueError:
            continue
        if a.version != 6 or not in_scope(a, cfg["scopes"]):
            continue  # link-local / out-of-scope — silently ignored (noise)

        gua = a.compressed
        if is_excluded(a, exclude_nets):
            unmapped.append({"gua": gua, "mac": e["mac"], "dev": e["dev"],
                             "reason": "excluded by config"})
            continue
        ipv4 = arp_map.get(e["mac"])
        if not ipv4:
            unmapped.append({"gua": gua, "mac": e["mac"], "dev": e["dev"],
                             "reason": "no IPv4 ARP entry for this MAC "
                                       "(no v4 name to borrow)"})
            continue
        if ipv4 not in cache:
            cache[ipv4] = resolver(ipv4)
        name = cache[ipv4]
        if not name:
            unmapped.append({"gua": gua, "mac": e["mac"], "dev": e["dev"],
                             "reason": f"IPv4 {ipv4} has no PTR record"})
            continue
        name = name.rstrip(".")
        if cfg["only_domain"] and not name.lower().endswith(cfg["only_domain"]):
            unmapped.append({"gua": gua, "mac": e["mac"], "dev": e["dev"],
                             "reason": f"borrowed name '{name}' outside "
                                       f"only_domain '{cfg['only_domain']}'"})
            continue
        observed[gua] = {"name": name, "mac": e["mac"], "v4": ipv4}
    return observed, unmapped


# --- state + reconcile ----------------------------------------------------
def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"version": 1, "records": {}}


def save_state_atomic(path, state):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".v6ptr.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # atomic on POSIX
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# --- zone lookup (authority for do-no-harm classification) ----------------
def make_zone_reader(cfg, dig_bin):
    """Return f(gua_str) -> {'ptr': name_or_None, 'ours': bool}.

    'ptr'  - current PTR name in the zone (no trailing dot), or None.
    'ours' - True iff a TXT at the same name equals our exact marker string.
             Recognition is by the tool's own authored token, never by the
             PTR merely matching a name we would derive. Requires dig; without
             it, 'ours' is always False (safe: no re-adoption, do-no-harm).
    """
    server = cfg["server"]
    port = str(cfg.get("port", 53))
    marker = cfg.get("marker_string")

    def read(gua):
        ptr, ours = None, False
        if dig_bin:
            r = subprocess.run([dig_bin, "+short", "-p", port, "@" + server,
                                "-x", gua], capture_output=True, text=True)
            if r.returncode == 0:
                lines = [l for l in r.stdout.strip().splitlines() if l]
                ptr = lines[0].rstrip(".") if lines else None
            if marker and ptr is not None:
                nib = ipaddress.ip_address(gua).reverse_pointer
                t = subprocess.run([dig_bin, "+short", "-p", port, "@" + server,
                                    "TXT", nib], capture_output=True, text=True)
                if t.returncode == 0:
                    for line in t.stdout.strip().splitlines():
                        # dig prints TXT values wrapped in quotes
                        val = line.strip().strip('"')
                        if val == marker:
                            ours = True
                            break
        else:
            try:
                ptr = socket.gethostbyaddr(gua)[0].rstrip(".")
            except (socket.herror, socket.gaierror):
                ptr = None
        return {"ptr": ptr, "ours": ours}
    return read


def reconcile(observed, state, grace_days, zone_reader, marker_enabled):
    """Do-no-harm reconcile with marker-proven re-adoption.

    Admission gate (your words): a PTR is acted on iff **no PTR exists**
    (create) OR **the tool knows it as its own** (manage). Knowledge of
    ownership is minted only by the tool's own creation — either recorded in
    the ledger, or, if the ledger was lost, proven by the tool's own TXT
    marker still present in the zone. It is never inferred from the PTR merely
    matching a name we would derive.

    Returns (ops, preexisting, readopted, records):
      ops        - create / overwrite / reap, each server-guarded
      preexisting- PTRs the tool did not author: never touched, only reported
      readopted  - our own records recovered from zone markers after ledger
                   loss (no DNS change; ledger rebuilt from authored provenance)
      records    - working ledger
    """
    now = time.time()
    grace = grace_days * 86400
    records = dict(state.get("records", {}))
    ops, preexisting, readopted = [], [], []

    for gua, info in observed.items():
        ptr = ipaddress.ip_address(gua).reverse_pointer
        name = info["name"]
        old = records.get(gua)

        if old is not None:
            # already in the ledger (we created it this run of history)
            if old.get("name") != name:
                ops.append({"kind": "overwrite", "gua": gua, "ptr": ptr,
                            "name": name, "prev_name": old.get("name"),
                            "mac": info["mac"], "v4": info.get("v4")})
            else:
                old["last_seen"] = now
            continue

        # unknown to the ledger: consult the zone
        z = zone_reader(gua)
        if z["ptr"] is None:
            ops.append({"kind": "create", "gua": gua, "ptr": ptr,
                        "name": name, "mac": info["mac"], "v4": info.get("v4")})
        elif marker_enabled and z["ours"]:
            # our own authored record, ledger lost -> re-adopt from provenance
            if z["ptr"] == name:
                records[gua] = {"ptr": ptr, "name": name, "mac": info["mac"],
                                "first_seen": now, "last_seen": now,
                                "readopted": True}
                readopted.append({"gua": gua, "name": name})
            else:
                # ours but the borrowed name changed -> guarded overwrite,
                # guard against the CURRENT zone value we just read
                ops.append({"kind": "overwrite", "gua": gua, "ptr": ptr,
                            "name": name, "prev_name": z["ptr"],
                            "mac": info["mac"], "v4": info.get("v4")})
        else:
            # a PTR exists that we did NOT author -> hands off, report only
            preexisting.append({"gua": gua, "ptr": ptr,
                                "existing": z["ptr"], "would_set": name})

    # absent devices: reap past grace, guarded so we only delete our own record
    for gua in list(records.keys()):
        if gua in observed:
            continue
        rec = records[gua]
        if now - rec.get("last_seen", 0) > grace:
            ops.append({"kind": "reap", "gua": gua,
                        "ptr": rec.get("ptr",
                              ipaddress.ip_address(gua).reverse_pointer),
                        "name": rec.get("name")})
        # else: within grace, leave record and PTR untouched

    return ops, preexisting, readopted, {"version": 1, "records": records}


# --- nsupdate emission (per-op, every mutation guarded) -------------------
def op_nsupdate_script(op, cfg):
    """One guarded nsupdate transaction for a single op. Every mutation
    asserts the tool's model of the record as a prerequisite, so the server
    refuses the change if reality has diverged:

      create    -> prereq nxrrset            (only if the name is empty)
      overwrite -> prereq yxrrset <prev>     (only if still exactly what we set)
      reap      -> prereq yxrrset <name>     (only if still exactly what we set)
    """
    # `server <addr> <port>` targets the published BIND (e.g. containerised on
    # a non-standard port). nsupdate's server-directive port overrides defaults.
    lines = [f"server {cfg['server']} {cfg.get('port', 53)}"]
    if cfg["zone"]:
        lines.append(f"zone {cfg['zone']}")
    k = op["kind"]
    marker = cfg.get("marker_string")
    if k == "create":
        lines.append(f"prereq nxrrset {op['ptr']} PTR")
        lines.append(f"update add {op['ptr']} {cfg['ttl']} PTR {op['name']}.")
        if marker:
            # co-located provenance receipt: proves WE made this record, so a
            # future run can safely re-adopt it even if the ledger is lost.
            lines.append(f'update add {op["ptr"]} {cfg["ttl"]} TXT "{marker}"')
    elif k == "overwrite":
        lines.append(f"prereq yxrrset {op['ptr']} PTR {op['prev_name']}.")
        lines.append(f"update delete {op['ptr']} PTR")
        lines.append(f"update add {op['ptr']} {cfg['ttl']} PTR {op['name']}.")
        # marker (if any) is unchanged by a rename; leave it in place
    elif k == "reap":
        lines.append(f"prereq yxrrset {op['ptr']} PTR {op['name']}.")
        lines.append(f"update delete {op['ptr']} PTR")
        if marker:
            # delete only our exact marker value, never any other TXT
            lines.append(f'update delete {op["ptr"]} TXT "{marker}"')
    lines.append("send")
    return "\n".join(lines) + "\n"


def materialize_key(cfg):
    """Resolve the TSIG key nsupdate should use. Returns (path, is_temp).

    If an inline secret is configured, write a BIND-format key file to a
    0600 temp file (preferring /dev/shm tmpfs so the secret stays in RAM and
    never touches persistent disk) and return (path, True); the caller deletes
    it after the run. This keeps the secret out of the process list (unlike
    nsupdate -y). Otherwise fall back to the configured keyfile path, or None.
    Inline secret takes precedence over keyfile when both are set.
    """
    if cfg.get("key_secret"):
        name = cfg.get("key_name") or "ddns-key"
        algo = cfg.get("key_algorithm") or "hmac-sha256"
        content = (f'key "{name}" {{\n'
                   f'    algorithm {algo};\n'
                   f'    secret "{cfg["key_secret"]}";\n'
                   f'}};\n')
        d = "/dev/shm" if (os.path.isdir("/dev/shm")
                           and os.access("/dev/shm", os.W_OK)) else None
        fd, path = tempfile.mkstemp(prefix=".v6ptr-key.", suffix=".conf", dir=d)
        with os.fdopen(fd, "w") as f:   # mkstemp creates the file mode 0600
            f.write(content)
        return path, True
    return (cfg["keyfile"] or None), False


def apply_ops(ops, records, cfg, nsupdate_bin, key_path):
    """Apply each op as its own guarded transaction; update the ledger per
    outcome. A refused prerequisite means reality diverged from our model, so
    we RELINQUISH the record (drop it from the ledger) and report it — the
    tool never fights another writer.

    Returns (applied, relinquished) for reporting."""
    now = time.time()
    applied, relinquished = 0, []
    for op in ops:
        args = [nsupdate_bin] + (["-k", key_path] if key_path else [])
        r = subprocess.run(args, input=op_nsupdate_script(op, cfg),
                           capture_output=True, text=True)
        ok = r.returncode == 0
        k = op["kind"]
        if k == "create":
            if ok:
                records[op["gua"]] = {
                    "ptr": op["ptr"], "name": op["name"], "mac": op.get("mac"),
                    "first_seen": now, "last_seen": now}
                applied += 1
            else:
                # nxrrset failed: something appeared we don't own. Don't claim.
                relinquished.append((op, r.stderr.strip()))
        elif k == "overwrite":
            if ok:
                prev = records.get(op["gua"], {})
                records[op["gua"]] = {
                    "ptr": op["ptr"], "name": op["name"], "mac": op.get("mac"),
                    "first_seen": prev.get("first_seen", now), "last_seen": now}
                applied += 1
            else:
                # yxrrset failed: changed out from under us -> back off for good
                records.pop(op["gua"], None)
                relinquished.append((op, r.stderr.strip()))
        elif k == "reap":
            # ok  -> our record still matched and was deleted
            # fail-> changed out from under us; we did NOT delete anything
            records.pop(op["gua"], None)
            if ok:
                applied += 1
            else:
                relinquished.append((op, r.stderr.strip()))
    return applied, relinquished


# --- dry-run debug rendering (only used without --apply) ------------------
def render_debug_header(cfg, args, ip_bin, dig_bin, nsupdate_bin,
                        counts, n_v6, n_v4):
    """Human-readable metadata block for the dry-run debug dump."""
    server = cfg["server"]
    port = cfg.get("port", 53)
    if cfg["resolver"] == "dig":
        name_how = f"dig +short -x  (system resolver, port 53)"
    else:
        name_how = "system gethostbyaddr (nsswitch / resolv.conf, port 53)"
    if dig_bin:
        zone_how = f"dig -p {port} @{server}  (authoritative, incl. TXT markers)"
    else:
        zone_how = "gethostbyaddr fallback (no TXT marker reads possible)"
    marker = (cfg["marker_string"] if cfg["marker_enabled"] else "disabled")
    if cfg.get("key_secret"):
        key_line = (f"inline ({cfg.get('key_name') or 'ddns-key'}, "
                    f"{cfg.get('key_algorithm') or 'hmac-sha256'}) "
                    "— temp 0600 keyfile at apply time")
    elif cfg["keyfile"]:
        key_line = f"file {cfg['keyfile']}"
    else:
        key_line = "NONE (unauthenticated update — not recommended)"
    ifaces = ", ".join(cfg["interfaces"]) if cfg["interfaces"] else "all"
    scopes = ", ".join(cfg["scopes"])
    L = [
        "# " + "=" * 70,
        f"#  v6ptr-sync {VERSION} — DRY RUN (no changes will be made)",
        "# " + "=" * 70,
        f"#  run at        : {time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
        f"#  config        : {args.config}",
        f"#  update target : {server}:{port}  (nsupdate + zone reads)",
        f"#  TSIG key      : {key_line}",
        f"#  name lookup   : {name_how}",
        f"#  zone reads    : {zone_how}",
        f"#  marker        : {marker}",
        f"#  scopes        : {scopes}",
        f"#  interfaces    : {ifaces}",
        f"#  grace         : {cfg['grace_days']} days",
        f"#  ip binary     : {ip_bin}",
        f"#  dig binary    : {dig_bin or '(not found)'}",
        f"#  neighbours    : {n_v6} v6 / {n_v4} v4 cache entries read",
        f"#  result        : {counts['observed']} mapped GUAs | "
        f"create {counts['create']} overwrite {counts['overwrite']} "
        f"reap {counts['reap']} | re-adopt {counts['readopt']} | "
        f"pre-existing {counts['preexisting']} | unmapped {counts['unmapped']}",
        "# " + "=" * 70,
    ]
    return "\n".join(L)


def render_op_heading(op):
    """Readable heading for one op: the real IPv6 address, compressed and
    expanded, plus what the tool intends and where the name came from."""
    a = ipaddress.ip_address(op["gua"])
    bar = "─" * 4
    lines = [f"# {bar} {a.compressed}  [{op['kind'].upper()}] "
             + "─" * max(2, 60 - len(a.compressed) - len(op['kind'])),
             f"#     expanded : {a.exploded}",
             f"#     PTR name : {op['ptr']}"]
    if op["kind"] == "create":
        lines.append(f"#     set name : {op['name']}"
                     + (f"   (borrowed from {op['v4']})" if op.get("v4") else ""))
    elif op["kind"] == "overwrite":
        lines.append(f"#     old name : {op['prev_name']}")
        lines.append(f"#     new name : {op['name']}"
                     + (f"   (borrowed from {op['v4']})" if op.get("v4") else ""))
    elif op["kind"] == "reap":
        lines.append(f"#     removing : {op['name']}   (device gone past grace)")
    return "\n".join(lines)


# --- main -----------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", default="/etc/v6ptr.ini")
    ap.add_argument("--apply", action="store_true",
                    help="actually push and commit state (default: dry-run)")
    ap.add_argument("--gen-marker-id", action="store_true",
                    help="print a fresh random marker id and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.gen_marker_id:
        print(secrets.token_hex(16))
        return

    cfg = load_config(args.config)
    cfg["exclude_nets"] = build_excludes(cfg["exclude"])
    ip_bin = resolve_binary("ip")
    nsupdate_bin = resolve_binary("nsupdate") if args.apply else None
    dig_bin = None
    try:
        dig_bin = resolve_binary("dig")
    except FileNotFoundError:
        if cfg["resolver"] == "dig":
            sys.exit("resolver=dig configured but dig not found")
        if cfg["marker_enabled"]:
            sys.exit("marker enabled but dig not found (needed to read TXT "
                     "markers for re-adoption)")
    resolver = ((lambda ip: reverse_resolve_dig(ip, dig_bin))
                if cfg["resolver"] == "dig" else reverse_resolve_system)
    zone_reader = make_zone_reader(cfg, dig_bin)

    v6 = parse_neigh(run_ip_neigh(ip_bin, "-6"))
    v4 = parse_neigh(run_ip_neigh(ip_bin, ""))
    arp_map = build_arp_map(v4)
    observed, unmapped = correlate(v6, arp_map, cfg, resolver)

    state = load_state(cfg["state_path"])
    ops, preexisting, readopted, new_state = reconcile(
        observed, state, cfg["grace_days"], zone_reader, cfg["marker_enabled"])
    records = new_state["records"]

    counts = {
        "observed": len(observed),
        "create": sum(o["kind"] == "create" for o in ops),
        "overwrite": sum(o["kind"] == "overwrite" for o in ops),
        "reap": sum(o["kind"] == "reap" for o in ops),
        "readopt": len(readopted),
        "preexisting": len(preexisting),
        "unmapped": len(unmapped),
    }

    # ---------------- dry-run: rich debug document to stdout ----------------
    if not args.apply:
        out = [render_debug_header(cfg, args, ip_bin, dig_bin, nsupdate_bin,
                                   counts, len(v6), len(v4)), ""]

        if unmapped:
            out.append("# ---- GUAs seen but NOT mapped "
                       + "-" * 40)
            for u in unmapped:
                a = ipaddress.ip_address(u["gua"])
                out.append(f"#   {a.compressed}")
                out.append(f"#       expanded : {a.exploded}")
                out.append(f"#       on iface : {u['dev']}   mac {u['mac']}")
                out.append(f"#       reason   : {u['reason']}")
            out.append("")

        if preexisting:
            out.append("# ---- pre-existing PTRs, left UNTOUCHED "
                       + "-" * 31)
            for p in preexisting:
                a = ipaddress.ip_address(p["gua"])
                out.append(f"#   {a.compressed}")
                out.append(f"#       expanded : {a.exploded}")
                out.append(f"#       in zone  : {p['existing']}  "
                           f"(would have set '{p['would_set']}')")
            out.append("")

        if readopted:
            out.append("# ---- re-adopted from our markers (ledger-only, no DNS) "
                       + "-" * 15)
            for r in readopted:
                a = ipaddress.ip_address(r["gua"])
                out.append(f"#   {a.compressed}  ->  {r['name']}")
            out.append("")

        if ops:
            out.append("# ---- transactions that WOULD be sent "
                       + "-" * 33 + "\n")
            for op in ops:
                out.append(render_op_heading(op))
                out.append(op_nsupdate_script(op, cfg))
        else:
            out.append("# no create/overwrite/reap actions this run.")

        out.append("# " + "=" * 70)
        out.append("#  DRY RUN — nothing written to DNS, state file untouched.")
        out.append("#  Re-run with --apply to push.")
        out.append("# " + "=" * 70)
        print("\n".join(out))
        return

    # ---------------- apply: terse, side-effecting --------------------------
    print(f"# observed {len(observed)} | create {counts['create']} "
          f"overwrite {counts['overwrite']} reap {counts['reap']} "
          f"| re-adopt {counts['readopt']} | pre-existing {counts['preexisting']}",
          file=sys.stderr)
    for p in preexisting:
        print(f"# pre-existing PTR, NOT managed: {p['gua']} -> '{p['existing']}'",
              file=sys.stderr)
    for a in readopted:
        print(f"# re-adopted from marker: {a['gua']} -> '{a['name']}'",
              file=sys.stderr)

    key_path, key_is_temp = materialize_key(cfg)
    try:
        applied, relinquished = apply_ops(ops, records, cfg, nsupdate_bin,
                                          key_path)
    finally:
        if key_is_temp and key_path and os.path.exists(key_path):
            try:
                os.unlink(key_path)
            except OSError:
                pass
    save_state_atomic(cfg["state_path"], records)
    print(f"applied {applied} op(s); ledger committed "
          f"({len(records)} records tracked)", file=sys.stderr)
    for op, err in relinquished:
        print(f"# RELINQUISHED {op['kind']} {op['gua']}: zone diverged from our "
              f"record (prerequisite failed) — left untouched, dropped from "
              f"ledger. {err}", file=sys.stderr)


if __name__ == "__main__":
    main()
