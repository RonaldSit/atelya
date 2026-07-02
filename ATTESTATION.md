# amem Attestation — Tamper-Evident Memory Audit Log

**Audience:** auditors, enterprise security reviewers, compliance officers.
**Scope:** the integrity mechanism over amem's append-only memory op-log.
**Honest one-liner:** every memory operation is cryptographically chained; any
modification, deletion, or reordering of past records is **detectable and locatable**.
This is **tamper-EVIDENT, not tamper-PROOF** — see the threat model below.

---

## 1. What is guaranteed (plain language)

amem records every memory operation (`add` / `update` / `supersede` / `forget` /
`key_conflict` / `flag` / `purge`) as one line in an append-only JSONL op-log.
The attestation layer wraps that log in a hash chain: each entry carries a SHA-256
(or HMAC-SHA256) digest of **its own content plus the previous entry's digest**.

Consequences:

- Change one byte of any past record → its digest no longer matches → `verify-chain`
  fails **at that exact sequence number**.
- Delete or reorder records → the chain linkage (`prev_hash`) breaks → detected.
- The final digest (**root commitment**) summarizes the entire history; anyone holding
  yesterday's root can prove today whether history was rewritten.

## 2. Chain specification (sufficient for independent implementation)

Each attestation entry is a JSON object:

```json
{
  "seq":        <int, 0-based, strictly consecutive>,
  "event_id":   <string, the op-log record id or a derived stable id>,
  "ts":         <RFC3339 UTC string derived from the event's created_at, or null>,
  "payload":    <the original op-log event, verbatim>,
  "prev_hash":  <hex digest of the previous entry; "GENESIS" for seq 0>,
  "curr_hash":  <hex digest, defined below>
}
```

**Canonical serialization** (the part most implementations get wrong): the hashed
message is produced with

```
canonical(x) = JSON.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False) as UTF-8
```

**Digest construction:**

```
fields    = { seq, event_id, ts, payload, prev_hash }        # everything except curr_hash
msg       = canonical(fields) + prev_hash_utf8
curr_hash = SHA-256(msg)                       # default mode
curr_hash = HMAC-SHA256(key, msg)              # keyed mode (see threat model)
root      = curr_hash of the last entry        # the commitment to the whole history
```

A third party can implement a verifier from this section alone, using only a standard
SHA-256/HMAC library. Our test suite includes exactly such an independent verifier
(standard-library only, no calls into amem code) to prove the spec is sufficient.

## 3. Threat model — what each mode does and does not defend

| Adversary capability | SHA-256 mode | HMAC-SHA256 mode (with secret key) |
|---|---|---|
| Modify / delete / reorder log **without** rebuilding the chain | ✅ detected, located | ✅ detected, located |
| Rebuild the entire chain after tampering (has write access, **no key**) | ❌ not detected by the chain alone — requires an externally anchored root to detect | ✅ detected (cannot recompute valid HMACs without the key) |
| Rebuild the chain **with** the HMAC key | — | ❌ not detected — key custody / separation of duties required |
| Destroy the log entirely | ❌ chain cannot prove existence — external root anchoring detects "history vanished" | ❌ same; anchoring required |

**Explicit non-claims (do not overstate):**
- This mechanism is **tamper-evident**, not tamper-proof. Data can still be altered;
  alteration becomes detectable.
- Full assurance requires **anchoring the root externally** (WORM storage, a notary
  service, a transparency log, or simply emailing the root to a separately-controlled
  mailbox on a fixed cadence) and **separation of duties** (the identity that can write
  the log should not control the anchor or the HMAC key).

## 4. Regulatory mapping (evidence, not automatic compliance)

This mechanism **provides evidence toward** the following requirements. It does not by
itself make a deployment compliant; controls around key custody, access, and anchoring
complete the picture.

| Framework | Provision | How attestation supports it |
|---|---|---|
| **EU AI Act** | **Article 12** (record-keeping): high-risk AI systems shall technically allow automatic recording of events (logs) over the system lifetime | Every memory event is logged append-only **and** integrity-chained; auditors can verify the record was not altered after the fact, and locate any alteration |
| **SOC 2** (Security / Processing Integrity) | Log integrity & change detection criteria | `verify-chain` gives a repeatable, nonzero-exit integrity check suitable for CI/scheduled controls; root commitments provide point-in-time evidence |
| **NIST SP 800-92** | Log integrity guidance (protect logs from unauthorized modification; detect tampering) | Hash-chained entries + external root anchoring implement the recommended integrity pattern |
| **GDPR** | Art. 17 erasure interplay | amem governance implements soft-forget (auditable) and hard-purge; the **purge action itself is a logged, chained event**, so exercising erasure does not silently rewrite history |

## 5. Auditor runbook (copy-paste)

```bash
# 1) Build the chain over a memory op-log (per-user JSONL file)
python3 amem_governance.py attest data/<user>.jsonl --out data/<user>.attest.jsonl
#    -> prints the ROOT COMMITMENT. Record/anchor it externally.

# 2) Verify integrity at any later time (exit code 0 = intact, 1 = tampered)
python3 amem_governance.py verify-chain data/<user>.attest.jsonl

# 3) Keyed mode (defends against credentialed re-chaining)
export AMEM_ATTEST_KEY="<secret held by the audit function, not by log writers>"
python3 amem_governance.py attest data/<user>.jsonl --out data/<user>.attest.jsonl
python3 amem_governance.py verify-chain data/<user>.attest.jsonl

# 4) Independent re-derivation (no amem code): implement §2 with any standard
#    SHA-256/HMAC library and compare digests. The repo's test suite contains a
#    reference independent verifier (tests/test_amem_attest.py, stdlib-only).
```

## 6. Operational guidance

- **Anchoring cadence:** attest at least daily (or per session close); store the root
  where log writers have no write access.
- **Key custody (HMAC mode):** the key belongs to the audit/compliance function.
  Never store it beside the log. Rotate on personnel change; re-attest after rotation.
- **Separation of duties:** the service account writing the op-log must not be able to
  modify anchored roots or read the HMAC key.
- **CI control:** run `verify-chain` on a schedule; alert on nonzero exit.

## 7. Verification methodology (how this is tested)

The test suite (`tests/test_amem_attest.py`, 19 cases, runs in CI) follows standard
cryptographic test practice:

- **Known-answer tests (NIST-style KAT):** fixed inputs pinned to exact expected
  SHA-256 and HMAC digests; any drift in serialization or hashing fails loudly.
- **Independent cross-verification:** a from-scratch, standard-library-only verifier
  re-derives every digest without calling amem code — proving the chain is externally
  reproducible, not merely self-consistent.
- **Adversarial cases:** modify-at-seq, delete, reorder, sequence gap, prev-hash
  splice, append forgery, wrong-key HMAC, keyless forgery.
- **Canonicalization stability:** key order, CJK/Unicode text, float formatting.
- Cryptographic primitives are the Python standard library's `hashlib`/`hmac`
  (no custom cryptography).

---

*Wording note for sales/marketing: describe this feature as "cryptographically
tamper-evident audit logging (hash-chained, EU AI Act Art. 12 record-keeping pattern)".
Do **not** describe it as "tamper-proof" or "immutable" — reviewers will (correctly)
push back, and §3 is the honest answer.*
