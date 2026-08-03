#!/usr/bin/env python3
"""amem_anchor.py — external checkpoint/witness ledger for amem attestation chains.

WHY: a hash chain alone cannot catch an attacker who REWRITES the whole chain
(tamper + re-chain: the file verifies internally) or DELETES it. The industry
answer is the transparency-log CHECKPOINT/WITNESS pattern: periodically publish
the log head to a place the log writer cannot touch, and later verify the
current log is CONSISTENT with every past checkpoint.

Standards followed (no homemade scheme):
  - RFC 6962 (Certificate Transparency): a log periodically publishes its head
    (tree size + root hash); consistency between two heads proves the newer log
    is an append-only SUPERSET of the older one. Our checkpoint carries the
    analogous (seq, n_entries, root).
  - C2SP tlog-checkpoint: "A log MUST not sign any checkpoint which is
    inconsistent with any checkpoint it previously signed."  `anchor` enforces
    exactly this before appending — it refuses (exit 2) if the chain being
    anchored conflicts with ANY prior checkpoint under the same label.
  - C2SP tlog-witness: same size with a DIFFERENT root hash is a conflict
    (HTTP 409 in the spec). `check` reports the same condition as
    "history rewritten (same-position different-root conflict)".
  - Secure logging (Schneier–Kelsey; Crosby–Wallach history trees): external
    commitments make history rewriting evident. HONEST NOTE: Merkle trees give
    O(log n) consistency proofs; amem's attest format is a LINEAR hash chain,
    so consistency vs a checkpoint is the O(1) lookup "does the entry at the
    anchored seq still carry the anchored hash" after an O(n) chain verify.
    Correct at our scales; deliberately not a Merkle log.
  - 2026 agent-audit practice (nono.sh, Apr 2026): per-session chains PLUS a
    hash-chained GLOBAL LEDGER, making "the host pretended this history never
    happened" detectable — not just "the host edited this history."

Separation of duties (Help Net Security, Apr 2026: "store the receipt where
the agent can't touch it"; the key lives outside the agent's trust boundary):
  - This module does NOT modify amem_attest / amem_governance.
  - The ledger has its OWN key namespace: --key/--keyfile/AMEM_ANCHOR_KEY,
    distinct from the chain's AMEM_ATTEST_KEY.
  - LIMIT THE MODULE CANNOT ENFORCE: anchoring only defeats a credentialed
    attacker if the ledger lives under SEPARATE control (different account /
    host / WORM store). A ledger on the same disk, writable by the same
    process, detects accidents — not a determined insider. Ops guidance:
    ATTESTATION.md §6.

Ledger entry (JSONL; hash construction REUSED from amem_attest.digest — one
canonical implementation in the codebase, zero drift):
  {"v":1, "kind":"amem-anchor-checkpoint", "anchored_at":"<RFC3339 UTC>",
   "label":"<chain identity — C2SP 'origin' analogue>",
   "seq":<last seq in chain, or null if empty>, "n_entries":<int>,
   "root":"<chain head curr_hash, or GENESIS if empty>",
   "prev_hash":"<previous ledger entry curr_hash, or GENESIS>",
   "curr_hash":"<SHA-256 or HMAC-SHA256 over canonical(fields)+prev_hash>"}

CLI:
  python amem_anchor.py anchor <chain.jsonl> --ledger <ledger.jsonl>
        [--label L] [--key K|--keyfile F] [--chain-key K|--chain-keyfile F]
        [--at 2026-01-01T00:00:00Z]
  python amem_anchor.py check  <chain.jsonl> --ledger <ledger.jsonl>
        [--label L] [--key ...] [--chain-key ...] [--require-anchor]
  python amem_anchor.py latest --ledger <ledger.jsonl> [--label L] [--key ...]
  python amem_anchor.py --selftest

Exit codes: 0 = ok · 1 = check/input failure · 2 = anchor refused
(invalid chain, or C2SP inconsistency with a previously anchored checkpoint).
"""

import argparse
import json
import os
import sys
import time
import signal

# ---- reuse amem_attest's canonical/digest/read/verify (ONE hash construction) ----
try:
    import amem_attest as attest
except ImportError:  # loaded from another cwd (e.g. tests/) — resolve next to this file
    import importlib.util

    _p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "amem_attest.py")
    _s = importlib.util.spec_from_file_location("amem_attest", _p)
    attest = importlib.util.module_from_spec(_s)
    _s.loader.exec_module(attest)

GENESIS = attest.GENESIS
KIND = "amem-anchor-checkpoint"
CP_FIELDS = ("v", "kind", "anchored_at", "label", "seq", "n_entries", "root", "prev_hash")


# ------------------------------------------------------------------ core ----
def make_entry(prev_hash, *, anchored_at, label, seq, n_entries, root, key=None):
    """Build one hash-chained checkpoint entry (exposed for tests)."""
    e = {
        "v": 1,
        "kind": KIND,
        "anchored_at": anchored_at,
        "label": label,
        "seq": seq,
        "n_entries": n_entries,
        "root": root,
        "prev_hash": prev_hash,
    }
    e["curr_hash"] = attest.digest(prev_hash, {k: e[k] for k in CP_FIELDS}, key)
    return e


def verify_ledger(entries, key=None):
    """O(n) integrity check of the anchor ledger's own hash chain.
    Returns (ok, first_bad_index, reason)."""
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("kind") != KIND or e.get("v") != 1:
            return False, i, "not an amem-anchor-checkpoint entry (kind/v mismatch)"
        if e.get("prev_hash") != prev:
            return False, i, "prev_hash does not match previous curr_hash (deletion/reorder)"
        recomputed = attest.digest(prev, {k: e.get(k) for k in CP_FIELDS}, key)
        if recomputed != e.get("curr_hash"):
            return False, i, "curr_hash mismatch (checkpoint modified after anchoring)"
        prev = e["curr_hash"]
    return True, None, f"intact: {len(entries)} checkpoint(s)"


def chain_head(chain):
    """(seq, n_entries, root) of an attest chain — RFC 6962 'tree head' analogue."""
    if not chain:
        return None, 0, GENESIS
    return chain[-1]["seq"], len(chain), chain[-1]["curr_hash"]


def consistency(chain, checkpoint):
    """Is the CURRENT chain an append-only superset of this checkpoint?
    (RFC 6962 consistency, linear-chain form.) Returns (ok, reason)."""
    n = checkpoint.get("n_entries", 0)
    if n == 0:
        return True, "empty checkpoint (consistent with any chain)"
    seq = checkpoint.get("seq")
    if seq is None or seq != n - 1:
        return False, "malformed checkpoint (seq/n_entries mismatch)"
    if len(chain) <= seq:
        return False, (
            f"chain has {len(chain)} entries but checkpoint anchors seq={seq}"
            " — history truncated/vanished below an anchored checkpoint"
        )
    if chain[seq].get("curr_hash") != checkpoint.get("root"):
        return False, (
            f"chain hash at seq={seq} != anchored root"
            " — history rewritten (same-position different-root conflict)"
        )
    return True, "consistent"


def monotonic(cps):
    """C2SP-witness ordering over a label's checkpoints: seq never decreases;
    equal seq must carry an equal root. Returns (ok, index, reason)."""
    last_seq, last_root, seen = None, None, False
    for i, checkpoint in enumerate(cps):
        seq = -1 if checkpoint.get("seq") is None else checkpoint["seq"]
        if seen:
            if seq < last_seq:
                return (
                    False,
                    i,
                    f"checkpoint seq decreased ({last_seq} -> {seq}) — witness-order violation",
                )
            if seq == last_seq and checkpoint.get("root") != last_root:
                return (
                    False,
                    i,
                    "same anchored position with a different root — conflict (C2SP 409 analogue)",
                )
        last_seq, last_root, seen = seq, checkpoint.get("root"), True
    return True, None, "monotonic"


# ------------------------------------------------------------------ io ----
def _read_ledger(path):
    return attest.read_jsonl(path) if os.path.exists(path) else []


def _append_ledger(path, entry):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _load_key(val, keyfile, env):
    if val is not None:
        print(
            "warning: inline key flags are visible in process listings and shell history; "
            f"prefer a keyfile or the {env} env var",
            file=sys.stderr,
        )
        if not val.strip():
            sys.exit(
                f"inline key given but empty/whitespace; refusing silent HMAC->SHA-256 downgrade ({env})"
            )
        return val.encode("utf-8")  # bytes taken literally (0.1.0-compatible)
    if keyfile:
        with open(keyfile, "rb") as f:
            k = f.read().strip()
        if not k:
            sys.exit(f"keyfile is empty: {keyfile}; refusing silent HMAC->SHA-256 downgrade")
        return k
    v = os.environ.get(env)
    if v is not None and not v.strip():
        sys.exit(f"{env} is set but empty; refusing silent HMAC->SHA-256 downgrade")
    return v.encode("utf-8") if v else None


def _now_rfc3339():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _valid_rfc3339(s):
    try:
        time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


# ------------------------------------------------------------------ cmds ----
def cmd_anchor(chain_path, ledger_path, label, akey, ckey, at):
    chain = attest.read_jsonl(chain_path)
    ok, bad, reason = attest.verify_chain(chain, ckey)
    if not ok:
        print(f"REFUSED — will not checkpoint an invalid chain (seq={bad}: {reason})")
        return 2
    seq, n, root = chain_head(chain)

    ledger = _read_ledger(ledger_path)
    ok, bad, reason = verify_ledger(ledger, akey)
    if not ok:
        print(f"REFUSED — anchor ledger fails integrity at index {bad}: {reason}")
        return 2

    cps = [e for e in ledger if e.get("label") == label]
    ok, bad, reason = monotonic(cps)
    if not ok:
        print(
            f"REFUSED — existing checkpoints for '{label}' violate witness order at #{bad}: {reason}"
        )
        return 2
    # C2SP tlog-checkpoint: MUST not sign a checkpoint inconsistent with any prior one.
    for i, checkpoint in enumerate(cps):
        ok, reason = consistency(chain, checkpoint)
        if not ok:
            print(
                f"REFUSED — chain is inconsistent with previously anchored checkpoint #{i} "
                f"(anchored_at {checkpoint.get('anchored_at')}): {reason}"
            )
            print(
                "  (C2SP tlog-checkpoint rule: a log MUST NOT sign a checkpoint "
                "inconsistent with one it previously signed.)"
            )
            return 2
    if cps and cps[-1].get("seq") == seq and cps[-1].get("root") == root:
        print(f"already anchored at this head (seq={seq}, root={str(root)[:16]}…) — no change")
        return 0

    prev = ledger[-1]["curr_hash"] if ledger else GENESIS
    entry = make_entry(prev, anchored_at=at, label=label, seq=seq, n_entries=n, root=root, key=akey)
    _append_ledger(ledger_path, entry)
    mode = "HMAC-SHA256" if akey else "SHA-256"
    print(f"anchored '{label}' head (seq={seq}, n={n}) -> {ledger_path}  (ledger mode: {mode})")
    print(f"  checkpoint root: {root}")
    print(
        "  NOTE: this ledger must live under SEPARATE control (different account/host/"
        "WORM store) to defeat a credentialed attacker — see ATTESTATION.md §6."
    )
    return 0


def cmd_check(chain_path, ledger_path, label, akey, ckey, require_anchor):
    chain = attest.read_jsonl(chain_path)
    ok, bad, reason = attest.verify_chain(chain, ckey)
    if not ok:
        print(f"FAIL — chain integrity: TAMPER DETECTED at seq={bad}: {reason}")
        return 1
    if not os.path.exists(ledger_path):
        print(f"FAIL — anchor ledger not found: {ledger_path}")
        return 1
    ledger = _read_ledger(ledger_path)
    ok, bad, reason = verify_ledger(ledger, akey)
    if not ok:
        print(f"FAIL — ledger integrity: TAMPER DETECTED at checkpoint #{bad}: {reason}")
        return 1

    cps = [e for e in ledger if e.get("label") == label]
    if not cps:
        other = sorted({e.get("label") for e in ledger if e.get("label")})
        if other:
            print(
                f"FAIL — no checkpoints for label '{label}', but the ledger holds labels {other}. "
                f"Pass --label <one of these>. (check defaults --label to the chain filename, so a "
                f"forgotten --label must not silently pass for a security tool.)"
            )
            return 1
        msg = f"no checkpoints found for label '{label}' — nothing anchored yet"
        if require_anchor:
            print(f"FAIL — {msg} (--require-anchor)")
            return 1
        print(f"WARN — {msg}")
        print(
            f"OK — chain intact ({len(chain)} entries), ledger intact ({len(ledger)} checkpoint(s)), "
            f"0 checkpoints to compare"
        )
        return 0

    ok, bad, reason = monotonic(cps)
    if not ok:
        print(f"FAIL — checkpoint order for '{label}' at #{bad}: {reason}")
        return 1
    for i, checkpoint in enumerate(cps):
        ok, reason = consistency(chain, checkpoint)
        if not ok:
            print(
                f"FAIL — ANCHOR CONFLICT vs checkpoint #{i} "
                f"(anchored_at {checkpoint.get('anchored_at')}, seq={checkpoint.get('seq')}): {reason}"
            )
            return 1
    last = cps[-1]
    tail = (len(chain) - 1) - (last["seq"] if last.get("seq") is not None else -1)
    print(
        f"VERIFIED — chain intact ({len(chain)} entries); ledger intact; "
        f"{len(cps)} checkpoint(s) for '{label}' all consistent (append-only history confirmed)"
    )
    print(
        f"  latest anchor: seq={last.get('seq')} at {last.get('anchored_at')}; "
        f"unanchored tail: {tail} entr{'y' if tail == 1 else 'ies'}"
        + ("" if tail == 0 else "  -> run `anchor` to cover them")
    )
    return 0


def cmd_latest(ledger_path, label, akey):
    if not os.path.exists(ledger_path):
        print(f"FAIL — anchor ledger not found: {ledger_path}")
        return 1
    ledger = _read_ledger(ledger_path)
    ok, bad, reason = verify_ledger(ledger, akey)
    if not ok:
        print(f"FAIL — ledger integrity: TAMPER DETECTED at checkpoint #{bad}: {reason}")
        return 1
    latest = {}
    for e in ledger:
        latest[e.get("label")] = e
    rows = [latest[label]] if label else list(latest.values())
    if label and label not in latest:
        print(f"no checkpoints for label '{label}'")
        return 1
    for e in rows:
        print(
            json.dumps(
                {k: e.get(k) for k in ("label", "seq", "n_entries", "root", "anchored_at")},
                ensure_ascii=False,
            )
        )
    return 0


# ------------------------------------------------------------------ main ----
def main(argv=None):
    if hasattr(signal, "SIGPIPE"):  # standard CLI: exit quietly (141) when piped to head/less
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = argparse.ArgumentParser(
        description="external checkpoint/witness ledger for amem attest chains"
    )
    parser.add_argument("cmd", nargs="?", choices=["anchor", "check", "latest"])
    parser.add_argument("chain", nargs="?")
    parser.add_argument("--ledger")
    parser.add_argument("--label")
    parser.add_argument("--key")
    parser.add_argument("--keyfile")
    parser.add_argument("--chain-key", dest="chain_key")
    parser.add_argument("--chain-keyfile", dest="chain_keyfile")
    parser.add_argument("--at")
    parser.add_argument("--require-anchor", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()
    if not args.cmd:
        print(
            "usage: amem_anchor.py {anchor|check|latest} [<chain.jsonl>] --ledger <ledger.jsonl> [...]"
        )
        return 1
    if not args.ledger:
        print("--ledger is REQUIRED (choose the separately-controlled location deliberately)")
        return 1
    akey = _load_key(args.key, args.keyfile, "AMEM_ANCHOR_KEY")
    ckey = _load_key(args.chain_key, args.chain_keyfile, "AMEM_ATTEST_KEY")

    if args.cmd == "latest":
        return cmd_latest(args.ledger, args.label, akey)
    if not args.chain or not os.path.exists(args.chain):
        print(f"chain file not found: {args.chain}")
        return 1
    label = args.label or os.path.basename(args.chain)
    if args.cmd == "anchor":
        at = args.at or _now_rfc3339()
        if not _valid_rfc3339(at):
            print(f"--at must be RFC3339 UTC like 2026-01-01T00:00:00Z (got: {at})")
            return 1
        return cmd_anchor(args.chain, args.ledger, label, akey, ckey, at)
    return cmd_check(args.chain, args.ledger, label, akey, ckey, args.require_anchor)


# ------------------------------------------------------------------ selftest ----
def _selftest():
    import tempfile

    d = tempfile.mkdtemp(prefix="anchor_")
    oplog = [
        {"op": "add", "id": "a", "text": "works at Acme", "key": "job", "created_at": 1.0},
        {
            "op": "add",
            "id": "b",
            "text": "allergic to penicillin",
            "key": "allergy",
            "created_at": 2.0,
        },
    ]
    chain_p, ledger_p = os.path.join(d, "c.jsonl"), os.path.join(d, "anchors.jsonl")

    def write_chain(events):
        chain_head = attest.build_chain(events, None)
        with open(chain_p, "w", encoding="utf-8") as f:
            for e in chain_head:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")

    write_chain(oplog)
    assert main(["anchor", chain_p, "--ledger", ledger_p, "--at", "2026-01-01T00:00:00Z"]) == 0
    assert main(["check", chain_p, "--ledger", ledger_p]) == 0
    # growth stays consistent (append-only superset passes)
    write_chain(oplog + [{"op": "forget", "id": "a", "created_at": 3.0}])
    assert main(["check", chain_p, "--ledger", ledger_p]) == 0
    assert main(["anchor", chain_p, "--ledger", ledger_p, "--at", "2026-01-02T00:00:00Z"]) == 0
    # credentialed attacker: rewrite history AND re-chain — chain verifies, anchor catches it
    evil = [
        dict(oplog[0], text="works at Evil"),
        oplog[1],
        {"op": "forget", "id": "a", "created_at": 3.0},
    ]
    write_chain(evil)
    assert attest.verify_chain(attest.read_jsonl(chain_p), None)[0], (
        "re-chained file verifies internally"
    )
    assert main(["check", chain_p, "--ledger", ledger_p]) == 1, (
        "anchor check must catch the rewrite"
    )
    assert main(["anchor", chain_p, "--ledger", ledger_p, "--at", "2026-01-03T00:00:00Z"]) == 2, (
        "anchor must REFUSE an inconsistent checkpoint (C2SP rule)"
    )
    # truncation below an anchored checkpoint
    write_chain(oplog[:1])
    assert main(["check", chain_p, "--ledger", ledger_p]) == 1, "history-vanished must be caught"
    print(
        "SELFTEST PASS: anchor/check, append-only growth, rewrite-after-anchor caught, "
        "C2SP refuse-inconsistent, truncation caught. (pure python, no GPU/API)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
