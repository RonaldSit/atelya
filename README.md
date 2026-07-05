# Atelya Attest

[![tests](https://github.com/RonaldSit/atelya/actions/workflows/tests.yml/badge.svg)](https://github.com/RonaldSit/atelya/actions/workflows/tests.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Dependencies: zero](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#)
<!-- pypi-badge -->

**Can you prove your AI agent's memory wasn't tampered with?**

Atelya Attest gives agent memory a cryptographic paper trail: every memory
operation is hash-chained, the chain head is checkpointed into an external
ledger (the RFC 6962 / C2SP transparency-log pattern), and verification names
the **exact record** that was modified, deleted, or reordered — including the
attack a plain hash chain cannot see: an insider who tampers **and re-chains**.

- 🔗 **Hash-chained op-log** — SHA-256 or HMAC-SHA256, one file, append-only
- 🕵️ **Pinpoint verification** — `TAMPER DETECTED at seq=N`, with the reason
- ⚓ **External checkpoints** — catch whole-history rewrites & silent deletion
- 🧾 **Governance CLI** — audit timeline, per-memory lineage, GDPR-correct
  erasure (soft-forget vs hard-purge, and the purge itself is a chained event)
- 🪶 **Zero dependencies** — Python 3.10+ standard library only, ~3 small files
- ✅ **38 tests** — known-answer vectors, stdlib-only independent verifiers,
  adversarial suite (rewrite-and-rechain, truncation, ledger tampering, …)

## Install

```bash
git clone https://github.com/RonaldSit/atelya.git
cd atelya
```

<!-- pip-install: enabled after PyPI publish -->

No `pip install` step is required to run the tools — they are stdlib-only.

## The 60-second proof

```bash
printf '%s\n' \
 '{"op":"add","id":"m1","text":"patient allergic to penicillin","key":"allergy"}' \
 '{"op":"add","id":"m2","text":"patient on warfarin 5mg daily","key":"medication"}' \
 > sample_oplog.jsonl

python3 amem_governance.py attest sample_oplog.jsonl --out chain.jsonl   # prints ROOT
python3 amem_governance.py verify-chain chain.jsonl                      # VERIFIED
sed -i 's/penicillin/aspirin/' chain.jsonl                               # attacker edits history
python3 amem_governance.py verify-chain chain.jsonl                      # TAMPER DETECTED at seq=0 (exit 1)
```

Change one byte of history — verification names the record that was touched.

## Use it from Python

```python
from amem_attest import build_chain, verify_chain, root_of

events = [
    {"op": "add", "id": "m1", "text": "patient allergic to penicillin", "key": "allergy"},
    {"op": "add", "id": "m2", "text": "patient on warfarin 5mg daily", "key": "medication"},
]

chain = build_chain(events, key=None)        # key=b"..." switches to HMAC-SHA256
print(root_of(chain))                        # the commitment you anchor / publish

ok, bad_seq, reason = verify_chain(chain, key=None)
print(ok, reason)                            # True  intact: 2 entries, root=…
```

Mutate any field of any entry and `verify_chain` returns
`(False, <seq>, <why>)` — sequence gaps, broken links, and payload edits are
all distinguished.

## The attack a chain alone cannot catch

An attacker with write access can tamper and **rebuild the whole chain** — the
file then verifies internally. The transparency-log answer: checkpoint the head
into a ledger the log writer cannot touch, and check consistency later.

```bash
python3 amem_attest.py attest sample_oplog.jsonl --out chain.jsonl
python3 amem_anchor.py anchor chain.jsonl --ledger /separate-control/anchors.jsonl

# attacker rewrites the op-log AND re-attests:
sed -i 's/penicillin/aspirin/' sample_oplog.jsonl
python3 amem_attest.py attest sample_oplog.jsonl --out chain.jsonl

python3 amem_attest.py verify chain.jsonl        # ✅ VERIFIED — the chain alone is blind
python3 amem_anchor.py check chain.jsonl --ledger /separate-control/anchors.jsonl
# -> ANCHOR CONFLICT … history rewritten (same-position different-root), exit 1
```

Run the anchor ledger under **separate control** (different account, host, or
WORM storage) and use different keys per role (`AMEM_ATTEST_KEY` vs
`AMEM_ANCHOR_KEY`) — separation of duties is what turns "detects accidents"
into "detects insiders".

## CLI reference

| Tool | Console command* | What it does |
|---|---|---|
| `amem_attest.py` | `atelya-attest` | `attest` an op-log into a hash chain; `verify` locates the exact bad record |
| `amem_anchor.py` | `atelya-anchor` | `anchor` chain heads into an external ledger; `check` detects rewrite-and-rechain & vanished history; `--require-anchor` CI gate |
| `amem_governance.py` | `atelya-govern` | audit timeline, per-memory lineage, retention, GDPR soft-forget / hard-purge, plus `attest` / `verify-chain` |

\* console commands are installed by the PyPI package; the `python3 file.py`
form always works from a clone.

Full flag reference, exact hash construction (precise enough to write your own
verifier), threat model, and auditor runbook: **[ATTESTATION.md](ATTESTATION.md)**.

## Why now

If your agents touch regulated workflows (health, finance, hiring, legal), EU
AI Act **Article 12** — automatic, verifiable event logging for high-risk
systems — becomes enforceable **August 2, 2026**. This layer produces the
evidence trail those audits ask for; the sources and control mapping
(EU AI Act / SOC 2 / NIST SP 800-92) live in [ATTESTATION.md](ATTESTATION.md).

## Honest scope

- **Tamper-evident, not tamper-proof.** Alterations become detectable and
  locatable, not impossible. The anchor ledger only defends against insiders if
  it lives under separate control.
- **Evidence toward compliance, not compliance itself.** No tool makes a
  deployment compliant by itself, and we won't claim otherwise.
- **Deliberately boring cryptography.** RFC 6962 / C2SP semantics, `hashlib` /
  `hmac` primitives, no custom crypto — auditors can read it, and the test
  suite includes a from-scratch stdlib verifier so you can re-implement
  verification independently.

## Tests

```bash
python3 -m pytest tests/ -q     # 38 passed
```

Known-answer vectors, standard-library-only independent verifiers (no circular
testing), and adversarial cases: modify / delete / reorder / splice / forgery /
wrong-key, rewrite-and-rechain, truncation-below-checkpoint, ledger tampering,
witness-order conflicts.

## About Atelya OS

This repo is the **open audit layer** of Atelya OS. The memory **engine** —
closed-API orchestration measured at ~90% memory-token savings on real API
runs, and KV-native serving for self-hosted inference — is not published here.
We're onboarding **3 design partners** ahead of the August 2 deadline:
**[open an issue](https://github.com/RonaldSit/atelya/issues)** to talk.

## Roadmap

- [ ] PyPI package (`pip install atelya-attest`)
- [ ] Anchor backends: S3 Object Lock (WORM) & RFC 3161 timestamp helper
- [ ] `examples/` — FastAPI middleware & nightly-verify cron recipes
- [ ] GitHub Action wrapping `--require-anchor` as a release gate

## License

Apache-2.0 — see [LICENSE](LICENSE).
