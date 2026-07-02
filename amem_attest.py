#!/usr/bin/env python3
"""amem_attest.py — tamper-EVIDENT, hash-chained attestation over amem's op-log.

The regulated-market (EU AI Act Art.12, SOC 2, FedRAMP) requirement that append-only
JSONL alone does NOT meet: *prove* no past record was modified, deleted, or reordered.
This adds the 2026-standard cryptographic layer ON TOP of the op-log, without touching
amem's core (same philosophy as amem_governance.py).

Standard followed (convergent across 2026 sources):
  - arXiv 2601.20727 "Audit Trails for Accountability in LLMs": each entry carries
    {event_id, RFC3339 ts, payload, prev_hash, curr_hash}; curr_hash = SHA-256 over
    serialized payload + prev_hash; first entry prev_hash = "GENESIS".
  - NIST SP 800-92 / Schneier-Kelsey secure-logging: chained integrity records.
  - Industry #1 failure point (multiple sources): CANONICAL serialization. We use
    json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False) so the hash
    is stable across machines, languages, and replays.

Two integrity modes (honest about what each guarantees):
  - SHA-256 (no key): tamper-EVIDENT. Detects modification/deletion/reorder by anyone
    who cannot also recompute the whole chain. (An attacker WITH write access could
    recompute it — that is the limit of plain hashing.)
  - HMAC-SHA256 (with --key / AMEM_ATTEST_KEY): tamper-evident even against an attacker
    who can rewrite the log, because they lack the secret to recompute valid hashes.

IMPORTANT (universal industry caveat): this is tamper-EVIDENT, not tamper-PROOF. Data
can still be altered; alteration becomes *detectable*. For full assurance, anchor the
printed root externally (WORM store, notary, or a transparency log) and restrict write
access (separation of duties).

CLI:
  python amem_attest.py attest <oplog.jsonl> [--out chain.jsonl] [--key KEY|--keyfile F]
  python amem_attest.py verify <chain.jsonl>  [--key KEY|--keyfile F]
  python amem_attest.py root   <chain.jsonl>
  python amem_attest.py --selftest
"""
import argparse, hashlib, hmac, json, os, sys, time, uuid

GENESIS = "GENESIS"


def canonical(payload) -> bytes:
    """Stable serialization — the cross-machine/replay-safe form (industry #1 gotcha)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(prev_hash: str, payload, key: bytes | None) -> str:
    """curr_hash = H(canonical(payload) + prev_hash). HMAC if key given, else SHA-256."""
    msg = canonical(payload) + prev_hash.encode("utf-8")
    if key:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


def read_jsonl(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def build_chain(events, key: bytes | None):
    """Wrap each op-log event into a hash-chained attestation entry."""
    chain, prev = [], GENESIS
    for seq, ev in enumerate(events):
        ts = ev.get("created_at")
        rfc3339 = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
                   if isinstance(ts, (int, float)) else None)
        entry = {
            "seq": seq,
            "event_id": ev.get("id") or f"evt-{uuid.uuid5(uuid.NAMESPACE_OID, str(seq)+canonical(ev).decode())}",
            "ts": rfc3339,
            "payload": ev,           # the original op-log event, verbatim
            "prev_hash": prev,
        }
        entry["curr_hash"] = digest(prev, _payload_for_hash(entry), key)
        chain.append(entry)
        prev = entry["curr_hash"]
    return chain


def _payload_for_hash(entry):
    """Hash covers everything that defines the entry EXCEPT curr_hash itself."""
    return {k: entry[k] for k in ("seq", "event_id", "ts", "payload", "prev_hash")}


def verify_chain(chain, key: bytes | None):
    """O(n) verification. Returns (ok, first_bad_seq, reason)."""
    prev = GENESIS
    for i, entry in enumerate(chain):
        if entry.get("seq") != i:
            return False, i, f"sequence gap/reorder: entry has seq={entry.get('seq')}, expected {i}"
        if entry.get("prev_hash") != prev:
            return False, i, "prev_hash does not match previous curr_hash (deletion/reorder)"
        recomputed = digest(prev, _payload_for_hash(entry), key)
        if recomputed != entry.get("curr_hash"):
            return False, i, "curr_hash mismatch (payload modified after attestation)"
        prev = entry["curr_hash"]
    return True, None, f"intact: {len(chain)} entries, root={prev[:16]}…"


def root_of(chain):
    return chain[-1]["curr_hash"] if chain else GENESIS


def _load_key(args):
    if getattr(args, "key", None):
        return args.key.encode("utf-8")
    if getattr(args, "keyfile", None):
        with open(args.keyfile, "rb") as f:
            return f.read().strip()
    env = os.environ.get("AMEM_ATTEST_KEY")
    return env.encode("utf-8") if env else None


def main(argv=None):
    ap = argparse.ArgumentParser(description="tamper-evident hash-chained attestation for amem op-log")
    ap.add_argument("cmd", nargs="?", choices=["attest", "verify", "root"])
    ap.add_argument("path", nargs="?")
    ap.add_argument("--out")
    ap.add_argument("--key")
    ap.add_argument("--keyfile")
    ap.add_argument("--selftest", action="store_true")
    A = ap.parse_args(argv)

    if A.selftest:
        return _selftest()
    if not A.cmd or not A.path:
        sys.exit("usage: amem_attest.py {attest|verify|root} <file> [--out chain.jsonl] [--key K|--keyfile F]")
    if not os.path.exists(A.path):
        sys.exit(f"file not found: {A.path}")
    key = _load_key(A)
    mode = "HMAC-SHA256 (tamper-evident vs. credentialed attacker)" if key else \
           "SHA-256 (tamper-evident vs. uncredentialed modification)"

    if A.cmd == "attest":
        events = read_jsonl(A.path)
        chain = build_chain(events, key)
        out = A.out or (A.path + ".attest.jsonl")
        with open(out, "w", encoding="utf-8") as f:
            for e in chain:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"attested {len(chain)} events -> {out}")
        print(f"  mode: {mode}")
        print(f"  root (commitment): {root_of(chain)}")
        print("  anchor this root externally (WORM/notary) for full assurance; this layer is tamper-EVIDENT, not tamper-PROOF.")
    elif A.cmd == "verify":
        chain = read_jsonl(A.path)
        ok, bad, reason = verify_chain(chain, key)
        print(f"  mode: {mode}")
        if ok:
            print(f"✅ VERIFIED — {reason}")
        else:
            print(f"❌ TAMPER DETECTED at seq={bad}: {reason}")
            return 1
    elif A.cmd == "root":
        print(root_of(read_jsonl(A.path)))
    return 0


def _selftest():
    import tempfile
    d = tempfile.mkdtemp()
    # a small op-log like amem memory.py emits
    events = [
        {"op": "add", "id": "a", "text": "user works at Boeing", "key": "employer", "created_at": 1.0},
        {"op": "add", "id": "b", "text": "user works at Airbus", "key": "employer", "created_at": 2.0},
        {"op": "update", "id": "b", "text": "user works at Airbus (verified)", "created_at": 3.0},
        {"op": "forget", "id": "a", "created_at": 4.0},
    ]
    for key in (None, b"super-secret-key"):
        chain = build_chain(events, key)
        ok, bad, _ = verify_chain(chain, key)
        assert ok, f"freshly built chain must verify (key={key is not None})"
        assert chain[0]["prev_hash"] == GENESIS, "first entry must chain to GENESIS"

        # 1) MODIFY a byte in a past payload -> must fail at that seq
        tampered = json.loads(json.dumps(chain))
        tampered[1]["payload"]["text"] = "user works at Boeing"   # attacker flips employer
        ok, bad, _ = verify_chain(tampered, key)
        assert not ok and bad == 1, f"modification must be detected at seq 1 (got ok={ok}, bad={bad})"

        # 2) DELETE an entry -> chain breaks (prev_hash mismatch)
        tampered = json.loads(json.dumps(chain))
        del tampered[1]
        for i, e in enumerate(tampered):     # renumber seq as a naive attacker would
            e["seq"] = i
        ok, bad, _ = verify_chain(tampered, key)
        assert not ok, "deletion must be detected"

        # 3) REORDER -> fails
        tampered = json.loads(json.dumps(chain))
        tampered[1], tampered[2] = tampered[2], tampered[1]
        ok, bad, _ = verify_chain(tampered, key)
        assert not ok, "reorder must be detected"

    # 4) HMAC: attacker without key cannot forge a valid chain
    chain = build_chain(events, b"real-key")
    forged = json.loads(json.dumps(chain))
    forged[1]["payload"]["text"] = "tampered"
    forged[1]["curr_hash"] = digest(forged[0]["curr_hash"], _payload_for_hash(forged[1]), b"attacker-guess")
    ok, _, _ = verify_chain(forged, b"real-key")
    assert not ok, "HMAC must reject a chain recomputed with the wrong key"

    # 5) canonical serialization is order-independent for dict keys
    assert canonical({"a": 1, "b": 2}) == canonical({"b": 2, "a": 1}), "canonical must be key-order stable"

    print("✅ amem_attest selftest passed: build/verify, modify@seq, delete, reorder, HMAC-forgery, canonical-stable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
