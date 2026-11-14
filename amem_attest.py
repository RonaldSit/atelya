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

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid
import signal

GENESIS = "GENESIS"
OPLOG_SCHEMA_VERSION = 2  # the highest op-log schema version build_chain reads (atelya W2)


def _schema_version(event, seq):
    """The op-log schema version of an event (absent = 1). ValueError for a version
    this code cannot read: a newer one, or one that is not a positive integer."""
    v = event.get("v", 1)
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise ValueError(f"event at seq {seq} has a schema version that is not a positive integer")
    if v > OPLOG_SCHEMA_VERSION:
        raise ValueError(
            f"event at seq {seq} has schema version {v}; this version reads op-logs up to "
            f"version {OPLOG_SCHEMA_VERSION}, so it was written by a newer version"
        )
    return v


def canonical(payload) -> bytes:
    """Stable serialization — the cross-machine/replay-safe form (industry #1 gotcha)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


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
    """Wrap each op-log event into a hash-chained attestation entry.

    Note: the ``key`` argument is the optional HMAC secret (bytes). It is
    unrelated to the per-event ``"key"`` field, which names the memory slot
    used for supersede semantics.

    Entry ts: a schema-2 event's own "ts" (RFC 3339, as written); otherwise, as
    before, its "created_at" to the second, or null. A version-1 entry is built
    exactly as before, so a chain rebuilt from an old op-log keeps its hashes.
    ValueError for an event of a schema version this code cannot read.
    """
    chain, prev = [], GENESIS
    for seq, event in enumerate(events):
        ts = event.get("created_at")
        if _schema_version(event, seq) >= 2 and isinstance(event.get("ts"), str):
            rfc3339 = event["ts"]
        else:
            rfc3339 = (
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
                if isinstance(ts, (int, float))
                else None
            )
        entry = {
            "seq": seq,
            "event_id": event.get("id")
            or f"evt-{uuid.uuid5(uuid.NAMESPACE_OID, str(seq) + canonical(event).decode())}",
            "ts": rfc3339,
            "payload": event,  # the original op-log event, verbatim
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


# ---- attest v2: a hash-only chain (atelya web3-features-spec W3) -------------------------
# Line entry:  {"v": 2, "seq": n, "line_sha256": <sha256 of the exact op-log line bytes, newline
#               excluded>, "prev": <sha256 of the previous entry's canonical JSON, or GENESIS>}
#              or, for a line whose content could be confirmed by guessing,
#              {"v": 2, "seq": n, "line_hmac": <HMAC-SHA256 with <data_dir>/.erasure_key>,
#               "keyed": true, "prev": ...}. No payload: the chain holds no text.
# Redaction:   {"v": 2, "redact": [seq, ...], "purge_marker": <id>, "prev": ...}, appended by a
#              hard purge after the lines it covers.
# Head:        sha256 of the last entry's canonical JSON (what an anchor commits to).
# Verifying keyed entries needs the data directory's .erasure_key; plain ones do not.
CHAIN_V2 = 2
_UUID4_HEX = re.compile(r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_LINE_KEYS = (
    frozenset(("v", "seq", "line_sha256", "prev")),
    frozenset(("v", "seq", "line_hmac", "keyed", "prev")),
)
_REDACT_KEYS = frozenset(("v", "redact", "purge_marker", "prev"))


def entry_hash(entry):
    """sha256 of an entry's canonical JSON: the next entry's prev, and the head."""
    return hashlib.sha256(canonical(entry)).hexdigest()


def chain_head_v2(chain):
    return entry_hash(chain[-1]) if chain else GENESIS


def is_v2(chain):
    return bool(chain) and isinstance(chain[0], dict) and chain[0].get("v") == CHAIN_V2


def unguessable(event):
    """True when the line names its record by a uuid4 in hex (122 random bits): hashing a
    guess of its content cannot confirm it, so its plain sha256 may be shown to anyone.
    Every id atelya writes today has 48 bits (12 hex), so all its lines are keyed."""
    rid = event.get("id") if isinstance(event, dict) else None
    return isinstance(rid, str) and _UUID4_HEX.fullmatch(rid) is not None


def _line_fields(raw, event, line_key):
    if unguessable(event):
        return {"line_sha256": hashlib.sha256(raw).hexdigest()}
    if not line_key:
        raise ValueError("a line without a uuid4 id needs the data directory's .erasure_key")
    return {"line_hmac": hmac.new(line_key, raw, hashlib.sha256).hexdigest(), "keyed": True}


def extend_chain_v2(chain, lines, line_key):
    """The chain followed by one entry per (raw line bytes, event) of lines, in order;
    seq continues after the last line entry."""
    out, prev = list(chain), chain_head_v2(chain)
    seq = sum(1 for e in chain if "seq" in e)
    for raw, event in lines:
        entry = {"v": CHAIN_V2, "seq": seq}
        entry.update(_line_fields(raw, event, line_key))
        entry["prev"] = prev
        out.append(entry)
        prev, seq = entry_hash(entry), seq + 1
    return out


def redaction_v2(chain, seqs, purge_marker):
    """The redaction record a hard purge appends: these seqs' lines are gone, on purpose."""
    return {
        "v": CHAIN_V2,
        "redact": sorted(set(seqs)),
        "purge_marker": purge_marker,
        "prev": chain_head_v2(chain),
    }


def verify_chain_v2(chain, lines, line_key):
    """Check a v2 chain against the op-log's lines [(raw bytes, event)], in order.

    Report: ok, verified (lines matched), redacted (seqs covered by redaction records),
    unattested (lines after the last attested one), head, last_seq, seq_of_line (each
    line's seq, None past the chain), error ({kind, seq, line, detail}; line is the index
    into lines). Kinds: not_v2, bad_entry, broken_link, redaction_before_line,
    key_missing, redacted_line_present, modified_line, reordered, inserted_line,
    missing_line. A missing line is accepted only when a redaction record chained
    after it covers its seq."""
    report = {
        "ok": False,
        "verified": 0,
        "redacted": 0,
        "unattested": 0,
        "head": chain_head_v2(chain),
        "last_seq": None,
        "seq_of_line": [None] * len(lines),
        "error": None,
    }

    def fail(kind, seq=None, line=None, detail=""):
        report["error"] = {"kind": kind, "seq": seq, "line": line, "detail": detail}
        return report

    entries, redacted, prev = [], set(), GENESIS
    for i, e in enumerate(chain):
        if not isinstance(e, dict) or e.get("v") != CHAIN_V2:  # True == 1, never 2
            return fail("not_v2" if i == 0 else "bad_entry", detail=f"chain entry {i}")
        if e.get("prev") != prev:
            return fail("broken_link", seq=e.get("seq"), detail=f"chain entry {i}: prev mismatch")
        keys = frozenset(e)
        if keys in _LINE_KEYS:
            seq, digest = e["seq"], e.get("line_sha256", e.get("line_hmac"))
            if (
                isinstance(seq, bool)
                or seq != len(entries)
                or not isinstance(digest, str)
                or not _HEX64.fullmatch(digest)
                or ("keyed" in e and e["keyed"] is not True)
            ):
                return fail("bad_entry", seq=seq, detail=f"chain entry {i}")
            entries.append(e)
        elif keys == _REDACT_KEYS:
            red = e["redact"]
            if (
                not isinstance(red, list)
                or not red
                or any(isinstance(x, bool) or not isinstance(x, int) for x in red)
            ):
                return fail("bad_entry", detail=f"chain entry {i}: redact")
            late = [x for x in red if not 0 <= x < len(entries)]
            if late:
                return fail("redaction_before_line", seq=late[0], detail=f"chain entry {i}")
            redacted.update(red)
        else:
            return fail("bad_entry", seq=e.get("seq"), detail=f"chain entry {i}: fields")
        prev = entry_hash(e)
    if any("keyed" in e for e in entries) and not line_key:
        return fail("key_missing", detail="keyed entries need the data directory's .erasure_key")
    cache = {}

    def match(e, k):
        if k not in cache:
            raw = lines[k][0]
            mac = hmac.new(line_key, raw, hashlib.sha256).hexdigest() if line_key else None
            cache[k] = (hashlib.sha256(raw).hexdigest(), mac)
        sha, mac = cache[k]
        return sha == e["line_sha256"] if "line_sha256" in e else mac == e["line_hmac"]

    for s in sorted(redacted):
        hit = next((k for k in range(len(lines)) if match(entries[s], k)), None)
        if hit is not None:
            return fail("redacted_line_present", seq=s, line=hit)
    live = [e for e in entries if e["seq"] not in redacted]
    i = 0
    for j, e in enumerate(live):
        if i < len(lines) and match(e, i):
            report["seq_of_line"][i] = e["seq"]
            i += 1
            continue
        if i >= len(lines):
            return fail("missing_line", seq=e["seq"], detail="the op-log ends before this line")
        later_entry = any(match(e2, i) for e2 in live[j + 1 :])
        later_line = any(match(e, k) for k in range(i + 1, len(lines)))
        if later_entry and later_line:
            kind = "reordered"
        elif later_entry:
            kind = "missing_line"
        elif later_line:
            kind = "inserted_line"
        else:
            kind = "modified_line"
        return fail(kind, seq=e["seq"], line=i)
    report.update(
        ok=True,
        verified=i,
        redacted=len(redacted),
        unattested=len(lines) - i,
        last_seq=entries[-1]["seq"] if entries else None,
    )
    return report


def _load_key(args):
    if getattr(args, "key", None) is not None:
        print(
            "warning: inline --key is visible in process listings and shell history; "
            "prefer --keyfile or AMEM_ATTEST_KEY",
            file=sys.stderr,
        )
        if not args.key.strip():
            sys.exit("--key given but empty/whitespace; refusing silent HMAC->SHA-256 downgrade")
        return args.key.encode("utf-8")  # bytes taken literally (0.1.0-compatible)
    if getattr(args, "keyfile", None):
        with open(args.keyfile, "rb") as f:
            k = f.read().strip()
        if not k:
            sys.exit(f"keyfile is empty: {args.keyfile}; refusing silent HMAC->SHA-256 downgrade")
        return k
    env = os.environ.get("AMEM_ATTEST_KEY")
    if env is not None and not env.strip():
        sys.exit("AMEM_ATTEST_KEY is set but empty; refusing silent HMAC->SHA-256 downgrade")
    return env.encode("utf-8") if env else None


def main(argv=None):
    if hasattr(signal, "SIGPIPE"):  # standard CLI: exit quietly (141) when piped to head/less
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = argparse.ArgumentParser(
        description="tamper-evident hash-chained attestation for amem op-log"
    )
    parser.add_argument("cmd", nargs="?", choices=["attest", "verify", "root"])
    parser.add_argument("path", nargs="?")
    parser.add_argument("--out")
    parser.add_argument("--key")
    parser.add_argument("--keyfile")
    parser.add_argument("--selftest", action="store_true")
    # parse_intermixed_args, not parse_args: on Python 3.10, 3.11, 3.12.0-3.12.6 and
    # 3.13.0, parse_args gives the optional positional zero strings when an option
    # follows the subcommand, then rejects the path as unrecognized. No subparsers,
    # REMAINDER or mutually exclusive groups here (parse_intermixed_args rejects them).
    args = parser.parse_intermixed_args(argv)

    if args.selftest:
        return _selftest()
    if not args.cmd or not args.path:
        sys.exit(
            "usage: amem_attest.py {attest|verify|root} <file> [--out chain.jsonl] [--key K|--keyfile F]"
        )
    if not os.path.exists(args.path):
        sys.exit(f"file not found: {args.path}")
    key = _load_key(args)
    mode = (
        "HMAC-SHA256 (tamper-evident vs. credentialed attacker)"
        if key
        else "SHA-256 (tamper-evident vs. uncredentialed modification)"
    )

    if args.cmd == "attest":
        events = read_jsonl(args.path)
        try:
            chain = build_chain(events, key)
        except ValueError as e:
            sys.exit(f"{args.path}: {e}; refusing to attest it")
        out = args.out or (args.path + ".attest.jsonl")
        with open(out, "w", encoding="utf-8") as f:
            for e in chain:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"attested {len(chain)} events -> {out}")
        print(f"  mode: {mode}")
        print(f"  root (commitment): {root_of(chain)}")
        print(
            "  anchor this root externally (WORM/notary) for full assurance; this layer is tamper-EVIDENT, not tamper-PROOF."
        )
    elif args.cmd == "verify":
        chain = read_jsonl(args.path)
        if is_v2(chain):
            sys.exit(_V2_ELSEWHERE % args.path)
        ok, bad, reason = verify_chain(chain, key)
        print(f"  mode: {mode}")
        if ok:
            print(f"✅ VERIFIED — {reason}")
        else:
            print(f"❌ TAMPER DETECTED at seq={bad}: {reason}")
            return 1
    elif args.cmd == "root":
        chain = read_jsonl(args.path)
        if is_v2(chain):
            sys.exit(_V2_ELSEWHERE % args.path)
        print(root_of(chain))
    return 0


_V2_ELSEWHERE = (
    "%s is an attest v2 chain (hashes only): verify it against its op-log with "
    "`atelya-govern verify-chain <chain> --oplog <oplog.jsonl>`; its head is printed there."
)


def _selftest():
    # a small op-log like amem memory.py emits
    events = [
        {
            "op": "add",
            "id": "a",
            "text": "user works at Boeing",
            "key": "employer",
            "created_at": 1.0,
        },
        {
            "op": "add",
            "id": "b",
            "text": "user works at Airbus",
            "key": "employer",
            "created_at": 2.0,
        },
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
        tampered[1]["payload"]["text"] = "user works at Boeing"  # attacker flips employer
        ok, bad, _ = verify_chain(tampered, key)
        assert not ok and bad == 1, (
            f"modification must be detected at seq 1 (got ok={ok}, bad={bad})"
        )

        # 2) DELETE an entry -> chain breaks (prev_hash mismatch)
        tampered = json.loads(json.dumps(chain))
        del tampered[1]
        for i, e in enumerate(tampered):  # renumber seq as a naive attacker would
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
    forged[1]["curr_hash"] = digest(
        forged[0]["curr_hash"], _payload_for_hash(forged[1]), b"attacker-guess"
    )
    ok, _, _ = verify_chain(forged, b"real-key")
    assert not ok, "HMAC must reject a chain recomputed with the wrong key"

    # 5) canonical serialization is order-independent for dict keys
    assert canonical({"a": 1, "b": 2}) == canonical({"b": 2, "a": 1}), (
        "canonical must be key-order stable"
    )

    print(
        "✅ amem_attest selftest passed: build/verify, modify@seq, delete, reorder, HMAC-forgery, canonical-stable."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
