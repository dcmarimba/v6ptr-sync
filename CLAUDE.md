# CLAUDE.md — invariants for v6ptr-sync

This tool writes to live DNS. Its entire value rests on a small set of
properties. **Do not weaken any of these to add a feature.** If a change seems
to require breaking one, that is a signal to stop and ask, not to proceed.

## Core invariant

**Never create over an existing PTR, and never overwrite or delete any record
whose current content the tool cannot account for as its own prior write.**

## Ownership is created, never inferred

- Ownership is minted ONLY by the tool's own successful `create` into an empty
  name, recorded in the JSON ledger.
- After a lost ledger, ownership is recovered ONLY by the tool's own authored
  `TXT` marker (`MARKER_SENTINEL:<id>`) being present in the zone.
- A PTR matching the name the tool *would* derive is NOT evidence of ownership.
  Do not re-introduce "adopt on name match." That was removed deliberately: a
  hand-maintained record can coincidentally match, and adopting it would let
  the tool clobber a record it never made.

## Every mutation must stay server-guarded

- create → `prereq nxrrset <name> PTR`
- overwrite → `prereq yxrrset <name> PTR <prev_name>`
- reap → `prereq yxrrset <name> PTR <prev_name>`
- A failed prerequisite means reality diverged → **relinquish** (drop from
  ledger, leave the zone untouched). Never "force" past a failed prereq.
- Do not batch ops in a way that loses per-op prerequisite outcomes.

## Pre-existing records are sacrosanct

- Any PTR the tool didn't author (no ledger entry, no matching marker) is
  reported and left untouched — regardless of scope, name, or match. Never
  add a code path that writes to such a name.
- The `exclude` list and interface allow-list are additional safety filters,
  not the primary protection; the ownership model is.

## Safe-by-default behaviour

- Dry-run is the DEFAULT. Only `--apply` may write to DNS or the ledger.
- The ledger is written atomically (temp file + `os.replace`). Keep it so.
- State-file loss must never cause harm: unknown-but-marked records re-adopt;
  unknown-and-unmarked records are left alone. Losing the marker `id` (in
  config) reverts to do-no-harm orphaning, never a clobber.

## Scope constraints

- Reverse-only. Do not add forward/AAAA writes without an explicit decision —
  it changes the safety surface (FCrDNS, name authority).
- Link-local is never a target. GUA by default; ULA only if configured.
- Stdlib-only. Do not add pip dependencies; the target host is sealed.
- Do not assume binary paths — resolve via `PATH` then explicit sbin/bin dirs.

## Testing

- `test_v6ptr.py` is the regression guard for all of the above. Any logic
  change must keep it green, and new behaviour affecting the ownership model
  must add a test. In particular, these must always pass:
  - do-no-harm on a matching-but-unmarked pre-existing PTR,
  - rejection of a wrong-id marker,
  - state-loss recovery via correct marker (no DNS writes),
  - guarded emission for create/overwrite/reap.
