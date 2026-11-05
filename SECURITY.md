# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅        |
| 0.1.x   | ❌        |

0.1.x is no longer supported. Its hard erase (`erase --hard`, `retention
--hard`) left traces of the erased records behind: `key_conflict` events
with an 80-character excerpt of the text, `flag` events kept by retention,
old-format lines without an id that matched but stayed in the file, purge
markers holding a plain SHA-256 of the erase pattern, and `.vec` lines of
ids the op-log no longer names. 0.2.0 removes all of these (see
CHANGELOG.md, 0.2.0). Upgrade to 0.2.0 or later: `pip install -U
"atelya-attest>=0.2.0"`. Existing op-logs need no migration. Upgrading does
not remove traces that a 0.1.x hard erase already left: `.vec` lines of ids
the op-log no longer names go at the next hard purge that matches a record,
but old `key_conflict` excerpts, `flag` events naming records purged
earlier, and plain SHA-256 markers stay in the op-log.

## Reporting a vulnerability

Please use **GitHub's private vulnerability reporting** for this repository:
**Security tab → "Report a vulnerability"**. Do not open public issues for
security reports.

- Acknowledgement: best effort within **72 hours** (this is a solo-maintained
  project; there is no on-call rotation).
- Coordinated disclosure: we will agree a timeline with you before any public
  advisory; credit is given unless you ask otherwise.
- No bug bounty is offered at this time.

## Scope

In scope: `amem_attest.py`, `amem_anchor.py`, `amem_governance.py` as shipped
in this repository and on PyPI (`atelya-attest`) — e.g. chain-verification
bypasses, hash/HMAC misuse, path handling, or anything that lets a modified
log verify as intact.

Out of scope (documented design, not vulnerabilities — see
**ATTESTATION.md · Threat model**):

- The chain is **tamper-EVIDENT, not tamper-proof**: an attacker who can
  rewrite *both* the log and the entire chain (and, in HMAC mode, holds the
  key) defeats local verification. That is exactly why the docs require
  anchoring the root externally (WORM store / notary / separately-controlled
  location) and separating duties.
- Denial of service against your own files (the tools operate on files you
  point them at).
