#!/usr/bin/env python3
"""Exercise the pure logic with representative `ip neigh` fixtures."""
import importlib.util, os, time, json, tempfile

spec = importlib.util.spec_from_file_location("v", os.path.join(os.path.dirname(__file__), "v6ptr-sync.py"))
v = importlib.util.module_from_spec(spec); spec.loader.exec_module(v)

# Representative plain-text output (no -j on this iproute2).
V6 = """\
2a00:1450:4009:1::100 dev bond1 lladdr 00:11:22:33:44:55 REACHABLE
2a00:1450:4009:1::a1b2:c3d4:e5f6 dev bond1 lladdr 00:11:22:33:44:55 STALE
fe80::211:22ff:fe33:4455 dev bond1 lladdr 00:11:22:33:44:55 router STALE
2a00:1450:4009:1::200 dev bond1 lladdr aa:bb:cc:dd:ee:ff DELAY
fd7a:beef:cafe::9 dev bond1 lladdr 11:22:33:44:55:66 STALE
2a00:1450:4009:1::300 dev bond1  FAILED
2a00:1450:4009:1::400 dev wan0 lladdr de:ad:be:ef:00:01 REACHABLE
"""

V4 = """\
192.168.10.100 dev bond1 lladdr 00:11:22:33:44:55 REACHABLE
192.168.10.200 dev bond1 lladdr aa:bb:cc:dd:ee:ff STALE
192.168.10.50 dev bond1  INCOMPLETE
10.0.0.1 dev wan0 lladdr de:ad:be:ef:00:01 REACHABLE
"""

# --- parser ---
v6e = v.parse_neigh(V6)
v4e = v.parse_neigh(V4)
assert len(v6e) == 7, len(v6e)
byaddr = {e["addr"]: e for e in v6e}
assert byaddr["2a00:1450:4009:1::100"]["mac"] == "00:11:22:33:44:55"
assert byaddr["2a00:1450:4009:1::100"]["state"] == "REACHABLE"
assert byaddr["2a00:1450:4009:1::100"]["dev"] == "bond1"
assert byaddr["fe80::211:22ff:fe33:4455"]["state"] == "STALE"  # router flag skipped
assert byaddr["2a00:1450:4009:1::300"]["mac"] is None          # FAILED, no lladdr
print("parse: OK  (router/proxy flags skipped, missing-lladdr handled)")

# --- arp map ---
arp = v.build_arp_map(v4e)
assert arp == {"00:11:22:33:44:55": "192.168.10.100",
               "aa:bb:cc:dd:ee:ff": "192.168.10.200",
               "de:ad:be:ef:00:01": "10.0.0.1"}, arp
print("arp map: OK  (INCOMPLETE with no mac dropped)")

# --- correlate (mock resolver + GUA-only scope) ---
NAMES = {"192.168.10.100": "laptop-1.example.com",
         "192.168.10.200": "cam-1.example.com",
         "10.0.0.1": "upstream-gw.example.net"}
cfg = {"interfaces": [], "scopes": ["gua"], "only_domain": ""}
obs, unmapped = v.correlate(v6e, arp, cfg, lambda ip: NAMES.get(ip))

# ::100 and ::a1b2... share one MAC -> both borrow laptop-1
assert obs["2a00:1450:4009:1::100"]["name"] == "laptop-1.example.com"
assert obs["2a00:1450:4009:1::100"]["v4"] == "192.168.10.100"  # borrow source recorded
assert obs["2a00:1450:4009:1:0:a1b2:c3d4:e5f6"]["name"] == "laptop-1.example.com"  # canonicalised
assert obs["2a00:1450:4009:1::200"]["name"] == "cam-1.example.com"
# fd7a... is ULA -> excluded by gua-only scope
assert not any(k.startswith("fd7a") for k in obs)
# fe80 link-local never in scope; ::300 FAILED skipped
assert not any(k.startswith("fe80") for k in obs)
assert "2a00:1450:4009:1::400" in obs  # wan0 device present when no iface filter
print(f"correlate: OK  ({len(obs)} GUAs; 1 MAC -> 2 GUAs confirmed; ULA/LL/FAILED excluded)")

# --- interface filter ---
cfg2 = dict(cfg, interfaces=["bond1"])
obs2, _ = v.correlate(v6e, arp, cfg2, lambda ip: NAMES.get(ip))
assert "2a00:1450:4009:1::400" not in obs2  # wan0 filtered out
print("interface filter: OK  (wan0 excluded)")

# --- only_domain filter (also exercises the unmapped diagnostic) ---
cfg3 = dict(cfg, only_domain="example.com")
obs3, unmapped3 = v.correlate(v6e, arp, cfg3, lambda ip: NAMES.get(ip))
assert "2a00:1450:4009:1::400" not in obs3  # example.net name rejected
# the rejected GUA should appear in unmapped with a domain-filter reason
assert any(u["gua"] == "2a00:1450:4009:1::400" and "only_domain" in u["reason"]
           for u in unmapped3)
print("only_domain filter: OK  (rejected name surfaced in unmapped diagnostics)")

# zone_reader stubs return {'ptr':..., 'ours':...} like the real reader
def zone(mapping):
    """mapping: gua -> (ptr_name_or_None, ours_bool). Missing gua => empty."""
    return lambda gua: {"ptr": mapping.get(gua, (None, False))[0],
                        "ours": mapping.get(gua, (None, False))[1]}
EMPTY_ZONE = zone({})
MARKER_ON = True

# --- cold start, empty zone -> all creates ---
ops, preex, readopt, st = v.reconcile(obs, {"version":1,"records":{}}, 14, EMPTY_ZONE, MARKER_ON)
creates = [o for o in ops if o["kind"] == "create"]
assert len(creates) == len(obs) and not preex and not readopt
print(f"reconcile cold start (empty zone): OK  ({len(creates)} creates)")

# --- create emits a co-located TXT marker ---
mcfg = {"server":"127.0.0.1","port":5353,"zone":"","ttl":300,"keyfile":"",
        "marker_string":"v6ptr-sync1:DEADBEEF"}
cscript = v.op_nsupdate_script(creates[0], mcfg)
assert "update add" in cscript and "PTR" in cscript
assert 'TXT "v6ptr-sync1:DEADBEEF"' in cscript
assert "server 127.0.0.1 5353" in cscript  # custom port reaches nsupdate
print("create writes marker: OK  (PTR + co-located TXT provenance, custom port)")

# --- DO NO HARM: pre-existing PTR, no marker (your hand-kept static host) ---
foreign = zone({"2a00:1450:4009:1::100": ("laptop-1.example.com", False)})
# note: PTR MATCHES what we'd derive, but no marker -> still hands off
ops_h, preex_h, readopt_h, st_h = v.reconcile(obs, {"version":1,"records":{}}, 14, foreign, MARKER_ON)
assert not any(o["gua"] == "2a00:1450:4009:1::100" for o in ops_h)
assert not any(a["gua"] == "2a00:1450:4009:1::100" for a in readopt_h)
assert "2a00:1450:4009:1::100" not in st_h["records"]
assert any(p["gua"] == "2a00:1450:4009:1::100" for p in preex_h)
print("do-no-harm (matching PTR, NO marker): OK  (your static host untouched)")

# --- SEEMINGLY SIMILAR marker with the WRONG id is NOT ours ---
# The real reader would compare the TXT to our exact marker; a different id
# yields ours=False. Simulate that: PTR present, ours=False.
wrong_id = zone({"2a00:1450:4009:1::100": ("laptop-1.example.com", False)})
ops_w, preex_w, readopt_w, _ = v.reconcile(obs, {"version":1,"records":{}}, 14, wrong_id, MARKER_ON)
assert not readopt_w and any(p["gua"] == "2a00:1450:4009:1::100" for p in preex_w)
print("wrong-id marker rejected: OK  (foreign/other-install marker != ours)")

# --- STATE-LOSS RECOVERY: ledger empty, but our marker is in the zone ---
# Same name in zone, ours=True -> re-adopt with NO DNS change.
recover = zone({
    "2a00:1450:4009:1::100": ("laptop-1.example.com", True),
    "2a00:1450:4009:1:0:a1b2:c3d4:e5f6": ("laptop-1.example.com", True),
    "2a00:1450:4009:1::200": ("cam-1.example.com", True),
    "2a00:1450:4009:1::400": ("upstream-gw.example.net", True),
})
ops_r, preex_r, readopt_r, st_r = v.reconcile(obs, {"version":1,"records":{}}, 14, recover, MARKER_ON)
# all four recovered, none required a DNS op, ledger rebuilt
assert not ops_r, ops_r
assert len(readopt_r) == len(obs)
assert st_r["records"]["2a00:1450:4009:1::100"]["readopted"] is True
print(f"state-loss recovery: OK  ({len(readopt_r)} records re-adopted from markers, 0 DNS writes)")

# --- our marker present but borrowed name has since changed -> guarded overwrite ---
recover_changed = zone({"2a00:1450:4009:1::100": ("old-name.example.com", True)})
# only feed the one GUA to keep it simple
obs_one = {"2a00:1450:4009:1::100": {"name":"laptop-1.example.com","mac":"00:11:22:33:44:55"}}
ops_rc, _, readopt_rc, _ = v.reconcile(obs_one, {"version":1,"records":{}}, 14, recover_changed, MARKER_ON)
assert len(ops_rc) == 1 and ops_rc[0]["kind"] == "overwrite"
assert ops_rc[0]["prev_name"] == "old-name.example.com"  # guard vs zone value
assert not readopt_rc
print("recovery + name drift: OK  (guarded overwrite against actual zone value)")

# Build a committed ledger to exercise owned-record paths.
st = {"version":1,"records":{}}
now = time.time()
for o in creates:
    st["records"][o["gua"]] = {"ptr":o["ptr"],"name":o["name"],"mac":o["mac"],
                               "first_seen":now,"last_seen":now}

# --- steady state -> no ops ---
ops2, pre2, rd2, _ = v.reconcile(obs, st, 14, EMPTY_ZONE, MARKER_ON)
assert ops2 == [] and pre2 == [] and rd2 == []
print("reconcile steady state: OK  (0 ops when ledger matches)")

# --- reap keeps TXT delete co-located ---
gone = "2a00:1450:4009:1::999"
st_stale = json.loads(json.dumps(st))
st_stale["records"][gone] = {"ptr": v.ipaddress.ip_address(gone).reverse_pointer,
    "name":"ghost.example.com","mac":"de:ad:de:ad:de:ad",
    "first_seen":time.time()-40*86400,"last_seen":time.time()-20*86400}
ops4, _, _, _ = v.reconcile(obs, st_stale, 14, EMPTY_ZONE, MARKER_ON)
reaps = [o for o in ops4 if o["kind"] == "reap"]
rscript = v.op_nsupdate_script(reaps[0], mcfg)
assert "prereq yxrrset" in rscript and "ghost.example.com" in rscript
assert "update delete" in rscript and 'TXT "v6ptr-sync1:DEADBEEF"' in rscript
print("reap deletes marker: OK  (guarded PTR delete + exact-value TXT delete)")

# --- TSIG key materialisation ---
import stat as _stat
kc_inline = {"key_secret":"c2VjcmV0YmFzZTY0","key_name":"ddns-key",
             "key_algorithm":"hmac-sha256","keyfile":""}
kp, is_tmp = v.materialize_key(kc_inline)
try:
    assert is_tmp and os.path.exists(kp)
    body = open(kp).read()
    assert 'key "ddns-key"' in body and "hmac-sha256" in body and "c2VjcmV0YmFzZTY0" in body
    assert _stat.S_IMODE(os.stat(kp).st_mode) == 0o600, "temp key must be 0600"
finally:
    os.unlink(kp)
kp2, is_tmp2 = v.materialize_key({"key_secret":"","keyfile":"/etc/v6ptr/ddns.key"})
assert not is_tmp2 and kp2 == "/etc/v6ptr/ddns.key"
kp3, is_tmp3 = v.materialize_key({"key_secret":"","keyfile":""})
assert not is_tmp3 and kp3 is None
print("TSIG key materialise: OK  (inline->0600 temp; file passthrough; none)")

# --- atomic state round-trip ---
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "sub", "state.json")
    v.save_state_atomic(p, st)
    assert json.load(open(p))["records"]["2a00:1450:4009:1::100"]["name"] == "laptop-1.example.com"
print("atomic state write: OK  (mkdir + atomic replace)")

print("\nALL TESTS PASSED")
