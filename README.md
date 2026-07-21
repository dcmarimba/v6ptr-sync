# v6ptr-sync

Populates **IPv6 GUA reverse (PTR) records** in an internal BIND zone by
borrowing hostnames from the dual-stacked IPv4 side — filling the gap left by
SLAAC, which (unlike DHCPv6) registers no DNS. Reverse-only, conservative, and
built around a strict *do-no-harm* ownership model: it only ever manages records
it created, and never touches anything it didn't.

Single-file, Python 3 standard library only. Designed to run on the gateway
(where the neighbour cache is most complete) and update a BIND server that may
be on another host and a non-standard port.

## Why this exists

DHCPv6 would give AAAA + PTR registration for free, but it's flaky and
incompletely supported (Android has never implemented stateful DHCPv6), so a
SLAAC-based network is the pragmatic reality. SLAAC hosts get global addresses
but no reverse DNS, so firewall/DNS logs show bare IPv6 addresses instead of
names. This tool fills that gap automatically, for the subset of hosts that
actually communicate (and therefore appear in the neighbour cache).

It is explicitly a *gap-filler*, not a source of truth: it maps what it can see,
accepts what it can't, and never risks existing records to do so.

## What it does

1. Reads the IPv6 neighbour cache (NDP) and the IPv4 ARP table via `ip neigh`.
2. **Joins them on MAC** — the device identity that survives RFC 8981 privacy
   addressing (one MAC, many rotating v6 addresses; all share one v4 name).
3. Filters to GUA (`2000::/3`) by default (ULA optional); link-local is never
   touched. Honours an interface allow-list and an address/prefix exclude-list.
4. Reverse-resolves each GUA's paired IPv4 address to a hostname (the "borrowed"
   name) via the system resolver.
5. Reconciles the desired PTRs against a JSON **ownership ledger** and the live
   zone, then emits guarded `nsupdate`/TSIG transactions.

## The ownership model (the important part)

The admission gate, in one line: **a PTR is acted on iff no PTR exists (create)
OR the tool knows it as its own (manage) — and nothing else.**

Ownership is **created, never inferred**. It is minted only by the tool's own
successful creation into empty space, recorded in the ledger — and, so it
survives a lost ledger, mirrored as a co-located `TXT` provenance marker in the
zone (`v6ptr-sync1:<per-install-id>`). A record is "ours" only if that exact
marker is present. A pre-existing PTR the tool didn't author — a hand-maintained
static host, say — is left untouched forever, whether or not its name matches
what the tool would derive.

Every mutation is guarded at the server by an `nsupdate` prerequisite, so BIND
refuses the change if reality has diverged from the tool's model:

| Action    | Guard                          | Meaning                              |
|-----------|--------------------------------|--------------------------------------|
| create    | `prereq nxrrset <name> PTR`    | only if the name is empty            |
| overwrite | `prereq yxrrset <name> PTR <prev>` | only if still exactly what we set |
| reap      | `prereq yxrrset <name> PTR <prev>` | only if still exactly what we set |

Any refused prerequisite → the tool **relinquishes** the record (drops it from
the ledger, leaves the zone alone) rather than fighting another writer. If the
ledger is lost, records carrying our marker are safely **re-adopted** from the
zone; records without it are never claimed.

Consequence: the tool cannot clobber a record it didn't create, even on first
run or after total state loss.

## How it works (data flow)

```
ip -6 neigh ─┐
             ├─ parse (plain text; no `ip -j` on old iproute2)
ip neigh ────┘
        │
        ├─ build_arp_map:  MAC -> IPv4
        └─ correlate:      for each in-scope GUA, MAC->IPv4->PTR(name)
                           => observed {gua: {name, mac, v4}}  + unmapped[]
        │
   reconcile(observed, ledger, zone_reader, marker):
        │   ledger hit  -> touch / guarded overwrite on name change
        │   ledger miss -> zone read:
        │                    no PTR        -> create
        │                    our marker    -> re-adopt (or guarded overwrite)
        │                    foreign PTR   -> pre-existing, leave untouched
        │   absent + past grace -> guarded reap
        │
   dry-run (default): render rich debug doc to stdout, write nothing
   --apply:           per-op guarded nsupdate; commit ledger per outcome
```

State is a JSON ledger written atomically (`os.replace`), keyed by canonical
GUA, holding `{ptr, name, mac, first_seen, last_seen}`. No database dependency.

## Requirements

- Python 3 (stdlib only: `json subprocess shutil ipaddress socket argparse
  secrets tempfile configparser time os`). No pip packages.
- `ip` (iproute2), `dig` and `nsupdate` (bind-utils) on `PATH` or in standard
  sbin/bin dirs. `dig`/`nsupdate` only needed for zone reads / applying.
- A BIND server authoritative for the target `ip6.arpa` reverse zone, accepting
  TSIG-authenticated dynamic updates.

## Configuration

Copy `v6ptr.ini.example` to a private `v6ptr.ini` (e.g. `/etc/v6ptr.ini`) and
edit. Key sections:

- `[dns]` — `server`, `port` (for BIND on a non-standard/published port),
  and the TSIG key: either `keyfile` (path to a BIND-format key file) **or**
  inline `key_name`/`key_algorithm`/`key_secret`. Inline wins if set; the tool
  writes a transient `0600` key file (in `/dev/shm` when available) so the
  secret never appears in the process list. `port` applies only to the
  update/zone-read path, not to the v4→name lookups.
- `[correlation]` — `interfaces` (allow-list; exclude the WAN side),
  `scopes` (`gua` or `gua,ula`), `resolver` (`system`|`dig`), `only_domain`,
  `exclude` (addresses/prefixes never to manage — e.g. static server GUAs),
  `grace_days` (reap delay; keep past the ~7-day privacy valid-lifetime).
- `[state]` — `path` to the JSON ledger.
- `[marker]` — `enabled` and `id`. Generate the id once with
  `python3 v6ptr-sync.py --gen-marker-id` and keep it (and the config) in your
  backups; it is the root of provenance identity across state loss.

## Usage

```bash
# generate a marker id once, paste into [marker] id in the config
python3 v6ptr-sync.py --gen-marker-id

# DRY RUN (default): reads everything, prints a full debug document, writes
# nothing to DNS or state. This is the safe default.
python3 v6ptr-sync.py -c /etc/v6ptr.ini

# APPLY: push guarded nsupdate transactions and commit the ledger.
python3 v6ptr-sync.py -c /etc/v6ptr.ini --apply

# run the test suite (no network/DNS touched)
python3 test_v6ptr.py
```

The dry-run document includes a metadata header (version, resolver methods,
update target `server:port`, TSIG key mode, scopes, grace), a per-entry heading
with the real IPv6 address (compressed and expanded), the exact `nsupdate`
transactions that *would* be sent, a list of **pre-existing** PTRs left
untouched, and a list of GUAs **seen but not mapped** with reasons.

Dry-run is a cold run every time (it never commits the ledger), so it is
slow — sequential DNS lookups for every GUA. A real `--apply` populates the
ledger; subsequent runs short-circuit known records and are fast.

## Deployment notes

- Run on the **gateway** — its neighbour cache/ARP table are the most complete.
  Coverage is bounded by the cache: only GUAs with recent traffic appear, and
  privacy GUAs can't be enumerated, only observed. This is accepted by design.
- **Cross-host / containerised BIND:** authorise updates by **TSIG key**, not
  source IP — container NAT may rewrite the source address. Publish the BIND
  port for **both UDP and TCP** (updates with a prereq + PTR + TXT can exceed
  512 bytes and fall to TCP). Keep both hosts **NTP-synced** (TSIG has a ~300s
  timestamp fudge; skew looks like a bad key).
- Reverse-only by design: these PTRs have no matching AAAA and won't
  forward-confirm (FCrDNS). Fine for log labelling; don't repurpose for
  forward-confirmed uses without revisiting.
- **Scheduling (TODO):** intended to run under a systemd oneshot + timer with
  journald logging. Units are not yet in the repo — see §"Roadmap".

## Roadmap / not-yet-done

- systemd `oneshot` service + `timer` units (planned; e.g. every 15 min).
- Optional parallel DNS lookups to speed cold runs (steady state is already
  fast; only cold/dry runs are slow).
- Optional AXFR-based eager ledger rebuild (current re-adoption is lazy: it
  recovers a marked record only when its GUA is next observed).

## Design provenance

Built iteratively with careful attention to a single guarantee: **never modify
a DNS record whose current content the tool cannot account for as its own prior
write.** See `CLAUDE.md` for the invariants any future change must preserve.
