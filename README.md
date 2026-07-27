# Atelya Attest

[![tests](https://github.com/RonaldSit/atelya/actions/workflows/tests.yml/badge.svg)](https://github.com/RonaldSit/atelya/actions/workflows/tests.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Dependencies: zero](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#)
[![PyPI](https://img.shields.io/pypi/v/atelya-attest)](https://pypi.org/project/atelya-attest/)

**Can you prove your AI agent's memory wasn't tampered with?**

Atelya Attest gives agent memory a cryptographic paper trail: every memory
operation is hash-chained, the chain head is checkpointed into an external
witness ledger, and GDPR erasure leaves a verifiable marker instead of a
silent hole. Pure Python stdlib — your auditor can rewrite the verifier in an
afternoon.

```bash
pip install atelya-attest
```

## 60-second proof

```bash
printf '{"op":"add","id":"m1","text":"patient allergic to penicillin","created_at":1718000000}\n' > log.jsonl
atelya-govern attest log.jsonl --out chain.jsonl
atelya-govern verify-chain chain.jsonl
# ✅ VERIFIED — intact: 1 entries, root=…

python3 -c "import pathlib as p; f=p.Path('chain.jsonl'); f.write_text(f.read_text().replace('penicillin','aspirin'))"
atelya-govern verify-chain chain.jsonl
# ❌ TAMPER DETECTED at seq=0: curr_hash mismatch  (exit 1 — CI-ready)
```

## What you get

| Capability | Command | The guarantee |
|---|---|---|
| Seal a memory log | `atelya-govern attest` | every event hash-chained; one ROOT commits the whole history |
| Verify integrity | `atelya-govern verify-chain` | a single flipped byte fails **at the exact record**, exit 1 |
| Keyed chains | `--key / --keyfile / $ENV` (HMAC-SHA-256) | wrong key fails; **empty/whitespace keys are refused** — no silent HMAC→SHA-256 downgrade |
| External anchoring | `atelya-anchor anchor / check / latest` | rewrite-and-rechain attacks surface as **ANCHOR CONFLICT**; a forgotten `--label` **fails loudly and lists what exists** instead of silently passing |
| GDPR erasure | `atelya-govern erase [--hard]` | soft = auditable forget (text retained); hard = content gone, marker records only a **SHA-256 digest** of the pattern — the erasure is provable, the secret never leaks |
| Audit views | `audit / lineage / conflicts / summary` | full timeline, one record's life, flagged contradictions |
| Retention | `retention --max-age / --max-active` | age/cap-based retirement, logged like everything else |
| Auditor export | `audit --out report.json` (or `.csv`) | machine-readable evidence for compliance packs |
| Self-tests | `--selftest` on all three tools | known-answer vectors, runnable anywhere, offline |

## How it works

```
 memory op-log (JSONL)        attest              external witness
 add / supersede / forget ──► hash chain ──ROOT──► ledger (append-only,
 erase(soft|hard)             (± HMAC)             monotonic, C2SP-style
        │                        │                 consistency checks)
        └── every event ─────────┘
```

- Each entry stores `prev_hash` + `curr_hash = H(prev ‖ payload)`; the final
  hash is the **ROOT** commitment.
- Anchoring follows the transparency-log discipline (RFC 6962 / C2SP
  tlog-checkpoint spirit): checkpoints must be **monotonic** and **consistent**
  with everything previously anchored — so rewriting history and re-chaining
  passes self-verification but is caught against the ledger.
- Everything is line-oriented JSON on disk. No database, no daemon, no
  network, no dependencies.

## Use it from Python

```python
from amem_attest import build_chain, verify_chain, root_of

events = [{"op": "add", "id": "m1", "text": "patient allergic to penicillin"}]
chain = build_chain(events, key=None)        # key=b"..." switches to HMAC-SHA256
print(root_of(chain))                        # the commitment you anchor / publish
ok, bad_seq, reason = verify_chain(chain, key=None)
```

Mutate any field of any entry and `verify_chain` returns `(False, <seq>, <why>)`
— sequence gaps, broken links, and payload edits are all distinguished.

## The attack a chain alone cannot catch

An attacker with write access can tamper **and rebuild the whole chain** — the
file then verifies internally. The transparency-log answer: checkpoint the head
into a ledger the writer cannot touch, then check consistency later.

```bash
atelya-attest attest log.jsonl --out chain.jsonl
atelya-anchor anchor chain.jsonl --ledger /separate-control/anchors.jsonl --label prod

# attacker rewrites the op-log AND re-attests the whole chain:
python3 -c "import pathlib as p; f=p.Path('log.jsonl'); f.write_text(f.read_text().replace('penicillin','aspirin'))"
atelya-attest attest log.jsonl --out chain.jsonl

atelya-attest verify chain.jsonl                 # ✅ VERIFIED — the chain alone is blind
atelya-anchor check chain.jsonl --ledger /separate-control/anchors.jsonl --label prod
# ❌ ANCHOR CONFLICT … history rewritten (same-position different-root) — exit 1
```

Run the ledger under **separate control** (different account/host/WORM store);
separation of duties is what turns "detects accidents" into "detects insiders".

## Guarantees — and non-guarantees

- **Tamper-EVIDENT, not tamper-proof.** Anyone claiming tamper-proof is
  overselling. Detection is the guarantee; prevention needs your storage
  controls, and rewrite-resistance needs the external anchor (shipped).
- A forgotten `--label` on `check` is treated as an operator error, not a
  pass: the tool fails and lists the labels the ledger actually holds.
- Hard-erase removes content but never the fact of erasure — the purge event
  itself is chained.
- Trust boundary: the verifier is ~200 lines of stdlib Python. Don't trust
  this repo — read it, or rewrite it.

## Verify it yourself

```bash
python -m pytest tests/ -q      # 63 tests: known-answer vectors, tz-matrix,
                                # tamper/reorder/truncation, erasure semantics
atelya-attest --selftest && atelya-anchor --selftest && atelya-govern --selftest
```

We pre-register benchmark pass lines and **publish the misses** — see
[CHANGELOG.md](CHANGELOG.md). The most recent full-system billing run missed
our own bar by 1.5 points; it's in there, dated.

## Where this fits

Atelya Attest is a **bolt-on evidence layer, not a memory store** — there is
nothing to migrate. If your memory system can emit one JSON event per line
(add / supersede / forget / erase), you get:

- a hash chain over that lifecycle, committed by a single ROOT
- pinpoint verification — `TAMPER DETECTED at seq=N`, exit 1, CI-ready
- external anchoring that catches whole-history rewrites
- GDPR soft-forget / hard-purge with sha256-digest markers
- auditor exports (JSON / CSV) and three offline `--selftest`s

Deliberately no performance comparisons: run your own eval, on your own data.

## Why now

The EU AI Act's logging/record-keeping duty (Art. 12) for high-risk AI
systems — is coming with runway: the Digital Omnibus moved standalone
high-risk (Annex III) duties to **2 December 2027**, while GDPR erasure is
enforceable **today** (dates verified 2026-07). This layer produces the
evidence trail those audits ask for; sources and control mapping
(EU AI Act / SOC 2 / NIST SP 800-92) live in [ATTESTATION.md](ATTESTATION.md).

## FAQ

**Is this "tamper-proof"?** No — tamper-evident, plus external anchoring
against rewrite-and-rechain. See *Guarantees* above.

**We already have a memory stack.** Keep it. If it can emit
JSONL events, the attest layer bolts on today — three commands, zero
dependencies, nothing replaced.

**You don't have SOC 2 — why would our auditor care?** Because they never
have to trust us: the verifier is stdlib, offline, and rewritable in an
afternoon, and our benchmark misses are published. Certifications are
roadmap; verifiability ships now.

## About Atelya OS

Atelya Attest is the open, self-verifiable layer of a larger system. The
engine — semantic memory with same-key supersede, a drop-in
closed-API orchestration and KV-native serving — is
not published here. Measured on our own bills, not extrapolated:
**2026-07-08** memory tokens **−76.8%** at turn 12 (**−84.5%** final turn);
full-system *including* the extraction tax **+33.5%**, which **missed our own
pre-registered line by 1.5 points — published as measured**. **2026-07-11**
self-hosted KV reuse: **6.12× cheaper prefill** at **96%** per-query agreement
(RTX 4070, n=200).

We're onboarding **3 design partners**: regulated teams who want the memory
layer *and* the evidence layer, with our hostile acceptance suites run on
their machines. → `ronald@atelyaos.com`

## Roadmap

- [x] PyPI package (`pip install atelya-attest`) — **0.1.1 published**
- [x] External anchor ledger with monotonic/consistency checks
- [x] SHA-256 erasure markers (never the literal pattern)
- [ ] Optional Ed25519 / ML-DSA signing (stdlib HMAC stays the default)
- [ ] Live-store invalidation hook for hard-erase (engine 0.3)

## Security & license

Vulnerabilities: see [SECURITY.md](SECURITY.md) (private reporting).
Apache-2.0 — see [LICENSE](LICENSE).
