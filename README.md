# Atelya Attest

**Tamper-evident audit layer for AI-agent memory.**
Hash-chained attestation over a memory op-log, plus an external checkpoint/witness
ledger (RFC 6962 / C2SP transparency-log pattern) that catches what a chain alone
cannot — an attacker who tampers **and re-chains**, or deletes history.

Built for teams who will have to show an auditor — or a regulator — that their
agent's memory history has not been silently altered. EU AI Act **Article 12**
(automatic event logging for high-risk systems) becomes enforceable
**August 2, 2026**; sources, threat model, and control mapping are in
**[ATTESTATION.md](ATTESTATION.md)**.

Zero dependencies. Python 3.10+ standard library only. Apache-2.0.

---

## The 60-second proof (run it yourself)

```bash
git clone https://github.com/RonaldSit/atelya.git && cd atelya
printf '%s\n' \
 '{"op":"add","id":"m1","text":"patient allergic to penicillin","key":"allergy","created_at":1718000000}' \
 '{"op":"add","id":"m2","text":"patient on warfarin 5mg daily","key":"medication","created_at":1718000100}' \
 > sample_oplog.jsonl

python3 amem_governance.py attest sample_oplog.jsonl --out chain.jsonl   # prints ROOT commitment
python3 amem_governance.py verify-chain chain.jsonl                      # VERIFIED
sed -i 's/penicillin/aspirin/' chain.jsonl                               # simulate an attacker
python3 amem_governance.py verify-chain chain.jsonl                      # TAMPER DETECTED at seq=0 (exit 1)
```

Change one byte of history — verification names the exact record that was touched.

### And the attack a chain alone cannot catch

An attacker with write access can tamper **and rebuild the whole chain** — the file
then verifies internally. The transparency-log answer: checkpoint the head into a
ledger the log writer cannot touch, and verify consistency later.

```bash
python3 amem_attest.py attest sample_oplog.jsonl --out chain.jsonl
python3 amem_anchor.py anchor chain.jsonl --ledger /separate-control/anchors.jsonl
# attacker rewrites the op-log AND re-attests:
sed -i 's/penicillin/aspirin/' sample_oplog.jsonl
python3 amem_attest.py attest sample_oplog.jsonl --out chain.jsonl
python3 amem_attest.py verify chain.jsonl                  # ✅ VERIFIED — chain alone is blind
python3 amem_anchor.py check chain.jsonl --ledger /separate-control/anchors.jsonl
#  -> ANCHOR CONFLICT … history rewritten (same-position different-root), exit 1
```

---

## What ships here

| File | What it does |
|---|---|
| `amem_attest.py` | SHA-256 / HMAC-SHA256 hash chain over an append-only op-log; `verify` locates the exact tampered/deleted/reordered record. |
| `amem_anchor.py` | External checkpoint/witness ledger (RFC 6962 head + C2SP tlog-checkpoint/witness rules, adapted to a linear chain): `anchor` refuses checkpoints inconsistent with prior ones; `check` detects rewrite-and-rechain and history-vanished; `--require-anchor` CI gate. Separate key namespace (`AMEM_ANCHOR_KEY` vs `AMEM_ATTEST_KEY`) for separation of duties. |
| `amem_governance.py` | Audit timeline, per-memory lineage, conflict decisions, retention windows, and GDPR-style erasure done right: **soft-forget (auditable) vs hard-purge (content removed — and the purge itself is a logged, chained event)**; `attest` / `verify-chain` subcommands. |
| `ATTESTATION.md` | The compliance spec: exact hash construction (precise enough to write your own verifier), honest threat model, EU AI Act / SOC 2 / NIST SP 800-92 mapping, auditor runbook, ops guidance. |
| `tests/` | 38 cases: NIST-style known-answer vectors, **standard-library-only independent verifiers** (no circular testing), and adversarial suites — modify / delete / reorder / splice / forgery / wrong-key, plus rewrite-and-rechain, truncation-below-checkpoint, ledger tampering, and witness-order conflicts. |

```bash
python3 -m pytest tests/ -q     # 38 passed
```

## Honest scope (read this — your reviewers will)

- **Tamper-EVIDENT, not tamper-proof.** Alterations become detectable and locatable,
  not impossible. Keyless mode defends against uncredentialed modification; HMAC mode
  defends against credentialed re-chaining; the anchor ledger defends against
  whole-history rewrites and deletion — **if it lives under separate control**
  (different account/host/WORM store). A ledger the same process can write detects
  accidents, not insiders.
- Attestation **provides evidence toward** EU AI Act Art. 12, SOC 2 log-integrity,
  and NIST SP 800-92 expectations. It does not, by itself, make a deployment
  compliant.
- Everything here is deliberately **standard** — RFC 6962 / C2SP semantics,
  `hashlib`/`hmac` primitives, no custom cryptography — because auditors should be
  able to read it, and because you should be able to re-implement verification
  independently (the tests include a from-scratch stdlib verifier as a recipe).

## About Atelya OS (what is *not* in this repo)

This repository is the **open audit layer** of Atelya OS. The memory **engine** —
closed-API orchestration measured at ~90% memory-token savings on real API runs, and
KV-native serving for self-hosted inference — is not published here and is available
to design partners. **Interested in a pilot before the August 2 deadline? Open a
GitHub issue on this repo.**

## License

Apache-2.0 — see [LICENSE](LICENSE).
