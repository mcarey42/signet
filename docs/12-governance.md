# 12 — Governance

**Status: Open**

## License

Apache-2.0 or MPL-2.0, decided **publicly before first code lands**. The
Vault→BSL relicense is why OpenBao exists; a trust-infrastructure project
cannot carry relicense risk. No CLA that enables relicensing; DCO sign-off.

Leaning: **Apache-2.0** (patent grant, maximal adoption).

Third-party license inventory (from E-03 selections): hashicorp/raft +
raft-boltdb are **MPL-2.0** — file-level copyleft, notice obligations only,
no viral effect on Apache-2.0 Signet code (precedent: rqlite/MIT ships
hashicorp/raft). bbolt is MIT. Watch item: an upstream BUSL relicense of
hashicorp/raft would trigger the pre-planned swap contained in the
`consensus` package (see E-03 §Confidence).

## Security process

- SECURITY.md with private disclosure channel from the first public release.
- Fuzz + interop CI matrix are release gates (10).
- Third-party audit before any 1.0 claim.

## Decision process

- Design docs in this directory are the record; substantive changes via PR
  with rationale. Status transitions (Open → Draft → Decided) happen in the
  doc itself.

## Open questions

- Governance home if adoption grows (independent org? foundation?) — decide
  when it matters, note it now so it's deliberate.
- Trademark/name check for "Signet" before public launch.
