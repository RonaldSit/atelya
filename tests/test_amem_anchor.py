#!/usr/bin/env python3
"""test_amem_anchor.py — industry-grade pytest suite for amem_anchor.py.

Same methodology as tests/test_amem_attest.py:
  1. KNOWN-ANSWER TESTS (NIST-style KAT): fixed inputs + injected RFC3339
     timestamps pinned to exact expected checkpoint hashes. Any drift in the
     canonical serialization or hash construction fails loudly.
  2. INDEPENDENT CROSS-VERIFICATION: a from-scratch, stdlib-only ledger
     verifier below re-derives every checkpoint hash from the documented spec
     without calling amem_anchor/amem_attest code — no circular testing.
  3. Adversarial cases as separate tests, led by the flagship scenario the
     chain alone cannot catch: REWRITE + RE-CHAIN (the tampered file verifies
     internally; the anchor check must still detect the conflict), plus
     truncation, C2SP refuse-inconsistent, idempotency, ledger tampering,
     wrong HMAC key, witness-order violations, and --require-anchor.

Run:  pytest tests/test_amem_anchor.py -v
"""

import copy
import hashlib
import hmac as hmac_mod
import importlib.util
import json
import os
import sys

import pytest

# ---- load the shipped modules from the repo root (parent of tests/) ---------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


attest = _load("amem_attest")
anchor = _load("amem_anchor")

# ---- fixed vectors (never change; pinned hashes below depend on them) -------
FIXED_EVENTS = [
    {"op": "add", "id": "kat1", "text": "known answer test", "key": "k", "created_at": 1000.0},
    {"op": "update", "id": "kat1", "text": "known answer test v2", "created_at": 2000.0},
]
GROWN_EVENTS = FIXED_EVENTS + [{"op": "forget", "id": "kat1", "created_at": 3000.0}]

CHAIN_ROOT = "3cf90e77411990073ee6e038d7a1ddfd90a34c284800a9560172e12aef4e4188"
CHAIN2_ROOT = "1738d9fc45d20c87443f0954aa8395f25bd5de940cfc98e9ea85a874062014e3"
KAT_AT_1, KAT_AT_2 = "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"
KAT_LABEL = "kat-chain"
KAT_CP_SHA256 = "f97313341fd75bd8369d23d89d7261d40f8cdb763d140981fde42a7958e6f5bf"
KAT_HMAC_KEY = b"anchor-test-vector-key"
KAT_CP_HMAC = "9524c507da05b285be8038699bcba8ff447acec9d0f2e711536b38d3ea6cf7cb"
KAT_CP2_SHA256 = "94e276f11a170f1c8d2321c0e31ff3a3e1a718d571a90929f8515bf5eb07cde8"


# ---- helpers -----------------------------------------------------------------
def write_chain(events, path):
    ch = attest.build_chain(events, None)
    with open(path, "w", encoding="utf-8") as f:
        for e in ch:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return ch


def write_ledger(entries, path):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


def _kat_head():
    chain = attest.build_chain(FIXED_EVENTS, None)
    return anchor.chain_head(chain)


# ---- 1. KNOWN-ANSWER TESTS ----------------------------------------------------
def test_kat_checkpoint_sha256_pinned():
    seq, n, root = _kat_head()
    assert root == CHAIN_ROOT, "attest KAT root drifted — fix attest first"
    e = anchor.make_entry(
        "GENESIS", anchored_at=KAT_AT_1, label=KAT_LABEL, seq=seq, n_entries=n, root=root, key=None
    )
    assert e["curr_hash"] == KAT_CP_SHA256, (
        "SHA-256 checkpoint hash drifted from pinned known-answer vector"
    )


def test_kat_checkpoint_hmac_pinned():
    seq, n, root = _kat_head()
    e = anchor.make_entry(
        "GENESIS",
        anchored_at=KAT_AT_1,
        label=KAT_LABEL,
        seq=seq,
        n_entries=n,
        root=root,
        key=KAT_HMAC_KEY,
    )
    assert e["curr_hash"] == KAT_CP_HMAC


def test_kat_second_checkpoint_chains_to_first():
    s2, n2, r2 = anchor.chain_head(attest.build_chain(GROWN_EVENTS, None))
    assert r2 == CHAIN2_ROOT
    e2 = anchor.make_entry(
        KAT_CP_SHA256,
        anchored_at=KAT_AT_2,
        label=KAT_LABEL,
        seq=s2,
        n_entries=n2,
        root=r2,
        key=None,
    )
    assert e2["prev_hash"] == KAT_CP_SHA256 and e2["curr_hash"] == KAT_CP2_SHA256


# ---- 2. INDEPENDENT CROSS-VERIFICATION (stdlib only; spec-derived) -----------
CP_FIELDS = ("v", "kind", "anchored_at", "label", "seq", "n_entries", "root", "prev_hash")


def _independent_verify_ledger(entries, key=None):
    """Re-derive every checkpoint hash from the documented spec ONLY:
    msg = canonical(fields incl. prev_hash) + prev_hash; H = HMAC/SHA-256."""
    prev = "GENESIS"
    for e in entries:
        fields = {k: e.get(k) for k in CP_FIELDS}
        msg = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        ) + prev.encode("utf-8")
        h = (
            hmac_mod.new(key, msg, hashlib.sha256).hexdigest()
            if key
            else hashlib.sha256(msg).hexdigest()
        )
        if e.get("prev_hash") != prev or e.get("curr_hash") != h:
            return False
        prev = e["curr_hash"]
    return True


def _two_cp_ledger(key=None):
    seq, n, root = _kat_head()
    e1 = anchor.make_entry(
        "GENESIS", anchored_at=KAT_AT_1, label=KAT_LABEL, seq=seq, n_entries=n, root=root, key=key
    )
    s2, n2, r2 = anchor.chain_head(attest.build_chain(GROWN_EVENTS, None))
    e2 = anchor.make_entry(
        e1["curr_hash"],
        anchored_at=KAT_AT_2,
        label=KAT_LABEL,
        seq=s2,
        n_entries=n2,
        root=r2,
        key=key,
    )
    return [e1, e2]


def test_independent_ledger_verifier_confirms_sha256():
    assert _independent_verify_ledger(_two_cp_ledger(None), None), (
        "stdlib-only re-derivation disagrees with the module (spec/impl mismatch)"
    )


def test_independent_ledger_verifier_confirms_hmac():
    assert _independent_verify_ledger(_two_cp_ledger(KAT_HMAC_KEY), KAT_HMAC_KEY)


def test_independent_ledger_verifier_catches_tamper():
    bad = copy.deepcopy(_two_cp_ledger(None))
    bad[0]["root"] = "0" * 64
    assert not _independent_verify_ledger(bad, None)


# ---- 3. ADVERSARIAL CASES ------------------------------------------------------
@pytest.fixture()
def paths(tmp_path):
    return str(tmp_path / "chain.jsonl"), str(tmp_path / "anchors.jsonl")


def test_anchor_then_check_verified(paths):
    chain_p, ledger_p = paths
    write_chain(FIXED_EVENTS, chain_p)
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1]) == 0
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 0


def test_rewrite_and_rechain_detected(paths):
    """Flagship: the attack the chain alone CANNOT catch."""
    chain_p, ledger_p = paths
    write_chain(FIXED_EVENTS, chain_p)
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1]) == 0
    evil = copy.deepcopy(FIXED_EVENTS)
    evil[0]["text"] = "tampered history"
    write_chain(evil, chain_p)  # attacker RE-CHAINS after tampering
    ok, _, _ = attest.verify_chain(attest.read_jsonl(chain_p), None)
    assert ok, "precondition: re-chained file must verify internally"
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 1, (
        "anchor check must detect the rewrite the chain alone cannot"
    )


def test_truncation_below_anchor_detected(paths):
    chain_p, ledger_p = paths
    write_chain(GROWN_EVENTS, chain_p)
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1]) == 0
    write_chain(FIXED_EVENTS[:1], chain_p)  # history "vanished"
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 1


def test_append_only_growth_passes_and_reports_tail(paths):
    chain_p, ledger_p = paths
    write_chain(FIXED_EVENTS, chain_p)
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1]) == 0
    write_chain(GROWN_EVENTS, chain_p)  # legitimate append-only growth
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 0
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_2]) == 0
    assert len(attest.read_jsonl(ledger_p)) == 2
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 0


def test_anchor_refuses_inconsistent_checkpoint_and_leaves_ledger_unchanged(paths):
    chain_p, ledger_p = paths
    write_chain(FIXED_EVENTS, chain_p)
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1]) == 0
    before = open(ledger_p, encoding="utf-8").read()
    evil = copy.deepcopy(FIXED_EVENTS)
    evil[1]["text"] = "conflicting history"
    write_chain(evil, chain_p)
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_2]) == 2, (
        "C2SP rule: MUST NOT sign a checkpoint inconsistent with a prior one"
    )
    assert open(ledger_p, encoding="utf-8").read() == before, "refusal must not append"


def test_reanchor_same_head_idempotent(paths):
    chain_p, ledger_p = paths
    write_chain(FIXED_EVENTS, chain_p)
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1]) == 0
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_2]) == 0
    assert len(attest.read_jsonl(ledger_p)) == 1, "same head must not duplicate a checkpoint"


def test_ledger_tamper_detected(paths):
    chain_p, ledger_p = paths
    write_chain(FIXED_EVENTS, chain_p)
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1]) == 0
    led = attest.read_jsonl(ledger_p)
    led[0]["root"] = "0" * 64  # tamper the receipt itself
    write_ledger(led, ledger_p)
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 1


def test_hmac_ledger_wrong_key_rejected(paths):
    chain_p, ledger_p = paths
    write_chain(FIXED_EVENTS, chain_p)
    assert (
        anchor.main(
            ["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1, "--key", "real-anchor-key"]
        )
        == 0
    )
    assert anchor.main(["check", chain_p, "--ledger", ledger_p, "--key", "wrong-key"]) == 1
    assert anchor.main(["check", chain_p, "--ledger", ledger_p, "--key", "real-anchor-key"]) == 0


def test_same_seq_different_root_conflict(paths):
    """C2SP tlog-witness 409 analogue, crafted with hash-valid entries."""
    chain_p, ledger_p = paths
    ch = write_chain(FIXED_EVENTS, chain_p)
    seq, n, root = anchor.chain_head(ch)
    e1 = anchor.make_entry(
        "GENESIS",
        anchored_at=KAT_AT_1,
        label="chain.jsonl",
        seq=seq,
        n_entries=n,
        root=root,
        key=None,
    )
    e2 = anchor.make_entry(
        e1["curr_hash"],
        anchored_at=KAT_AT_2,
        label="chain.jsonl",
        seq=seq,
        n_entries=n,
        root="f" * 64,
        key=None,
    )
    write_ledger([e1, e2], ledger_p)
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 1


def test_seq_decrease_witness_order_violation(paths):
    chain_p, ledger_p = paths
    ch = write_chain(GROWN_EVENTS, chain_p)
    s2, n2, r2 = anchor.chain_head(ch)
    e1 = anchor.make_entry(
        "GENESIS",
        anchored_at=KAT_AT_1,
        label="chain.jsonl",
        seq=s2,
        n_entries=n2,
        root=r2,
        key=None,
    )
    e2 = anchor.make_entry(
        e1["curr_hash"],
        anchored_at=KAT_AT_2,
        label="chain.jsonl",
        seq=0,
        n_entries=1,
        root=ch[0]["curr_hash"],
        key=None,
    )
    write_ledger([e1, e2], ledger_p)
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 1


def test_require_anchor_flag(paths):
    chain_p, ledger_p = paths
    write_chain(FIXED_EVENTS, chain_p)
    other = anchor.make_entry(
        "GENESIS",
        anchored_at=KAT_AT_1,
        label="some-other-chain",
        seq=1,
        n_entries=2,
        root="a" * 64,
        key=None,
    )
    # (a) nothing anchored at all -> warn only; --require-anchor turns it into a CI gate
    write_ledger([], ledger_p)
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 0  # warn only
    assert anchor.main(["check", chain_p, "--ledger", ledger_p, "--require-anchor"]) == 1  # CI gate
    # (b) the ledger DOES hold checkpoints, just under another label: a forgotten --label
    # must never silently pass for a security tool -> fail loudly, listing what exists
    write_ledger([other], ledger_p)
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 1
    assert anchor.main(["check", chain_p, "--ledger", ledger_p, "--label", "some-other-chain"]) != 0


def test_empty_chain_checkpoint(paths):
    chain_p, ledger_p = paths
    open(chain_p, "w").close()
    assert anchor.main(["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1]) == 0
    assert anchor.main(["check", chain_p, "--ledger", ledger_p]) == 0
    cp = attest.read_jsonl(ledger_p)[0]
    assert cp["n_entries"] == 0 and cp["seq"] is None and cp["root"] == "GENESIS"


def test_unicode_label(paths):
    chain_p, ledger_p = paths
    write_chain(FIXED_EVENTS, chain_p)
    assert (
        anchor.main(
            ["anchor", chain_p, "--ledger", ledger_p, "--at", KAT_AT_1, "--label", "病歷鏈-alice"]
        )
        == 0
    )
    assert anchor.main(["check", chain_p, "--ledger", ledger_p, "--label", "病歷鏈-alice"]) == 0
    assert _independent_verify_ledger(attest.read_jsonl(ledger_p), None)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
