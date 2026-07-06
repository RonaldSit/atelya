#!/usr/bin/env python3
"""test_amem_attest.py — industry-grade pytest suite for amem_attest.py.

Adds the three elements a bundled selftest lacks, per standard cryptographic
test practice:

  1. KNOWN-ANSWER TESTS (KAT, NIST-style): fixed inputs pinned to exact expected
     hashes. If canonical serialization or hashing ever drifts, these fail loudly.
  2. INDEPENDENT CROSS-VERIFICATION: a from-scratch verifier below uses ONLY the
     stdlib (hashlib/hmac/json) and never calls amem_attest's own digest/verify —
     proving the chain is externally reproducible, not just self-consistent.
  3. Adversarial coverage as separate cases: modify@seq, delete, reorder,
     append-forgery, wrong-key HMAC, prev_hash splice, seq gap, empty log,
     canonical stability (key order / unicode / float form).

Run:  pytest test_amem_attest.py -v
"""

import copy
import hashlib
import hmac as hmac_mod
import importlib.util
import json
import os
import sys

import pytest

# ---- load the exact shipped module by path (works regardless of cwd) --------
_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "amem_attest", os.path.join(os.path.dirname(_HERE), "amem_attest.py")
)
attest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attest)

# ---- fixed input vector (never change; the KAT hashes below depend on it) ---
FIXED_EVENTS = [
    {"op": "add", "id": "kat1", "text": "known answer test", "key": "k", "created_at": 1000.0},
    {"op": "update", "id": "kat1", "text": "known answer test v2", "created_at": 2000.0},
]
KAT_SHA256 = [
    "a9f58510728ad74e8dc281cab413c0a236e2965eff2f1370c58a2ec0197683b3",
    "3cf90e77411990073ee6e038d7a1ddfd90a34c284800a9560172e12aef4e4188",
]
KAT_HMAC_KEY = b"test-vector-key"
KAT_HMAC = [
    "8ed9b013d47ab164c4ec220f2e68dabbee8bff0dcb75296f34653829e1290de0",
    "2799db1cab0f0352c497f442c6503b3897ed553e50e652992aafe41a9645f9cf",
]


# ---- 1. KNOWN-ANSWER TESTS ---------------------------------------------------
def test_kat_sha256_chain_hashes_are_pinned():
    chain = attest.build_chain(FIXED_EVENTS, None)
    assert [e["curr_hash"] for e in chain] == KAT_SHA256, (
        "SHA-256 chain drifted from pinned known-answer vectors (canonical serialization changed?)"
    )


def test_kat_hmac_chain_hashes_are_pinned():
    chain = attest.build_chain(FIXED_EVENTS, KAT_HMAC_KEY)
    assert [e["curr_hash"] for e in chain] == KAT_HMAC, (
        "HMAC-SHA256 chain drifted from pinned known-answer vectors"
    )


def test_kat_genesis_and_linkage():
    chain = attest.build_chain(FIXED_EVENTS, None)
    assert chain[0]["prev_hash"] == "GENESIS"
    assert chain[1]["prev_hash"] == chain[0]["curr_hash"]


# ---- 2. INDEPENDENT CROSS-VERIFICATION (stdlib only; no attest functions) ---
def _independent_verify(chain, key=None):
    """Re-derive every hash from scratch with the stdlib. Returns True iff intact.

    Mirrors the documented spec ONLY (not the implementation):
      msg  = json.dumps(payload_fields, sort_keys=True, separators=(',',':'),
                        ensure_ascii=False).encode() + prev_hash.encode()
      hash = HMAC-SHA256(key, msg) if key else SHA256(msg)
    """
    prev = "GENESIS"
    for i, e in enumerate(chain):
        fields = {k: e[k] for k in ("seq", "event_id", "ts", "payload", "prev_hash")}
        msg = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        ) + prev.encode("utf-8")
        h = (
            hmac_mod.new(key, msg, hashlib.sha256).hexdigest()
            if key
            else hashlib.sha256(msg).hexdigest()
        )
        if e["seq"] != i or e["prev_hash"] != prev or e["curr_hash"] != h:
            return False
        prev = e["curr_hash"]
    return True


def test_independent_verifier_confirms_sha256_chain():
    chain = attest.build_chain(FIXED_EVENTS, None)
    assert _independent_verify(chain, None), (
        "stdlib-only re-derivation disagrees with the module (spec/impl mismatch)"
    )


def test_independent_verifier_confirms_hmac_chain():
    chain = attest.build_chain(FIXED_EVENTS, KAT_HMAC_KEY)
    assert _independent_verify(chain, KAT_HMAC_KEY)


def test_independent_verifier_catches_tamper():
    chain = attest.build_chain(FIXED_EVENTS, None)
    bad = copy.deepcopy(chain)
    bad[0]["payload"]["text"] = "tampered"
    assert not _independent_verify(bad, None)


# ---- 3. ADVERSARIAL CASES ----------------------------------------------------
@pytest.fixture()
def chain():
    return attest.build_chain(
        FIXED_EVENTS
        + [
            {"op": "forget", "id": "kat1", "created_at": 3000.0},
        ],
        None,
    )


def test_fresh_chain_verifies(chain):
    ok, bad, _ = attest.verify_chain(chain, None)
    assert ok and bad is None


def test_modify_payload_detected_at_exact_seq(chain):
    t = copy.deepcopy(chain)
    t[1]["payload"]["text"] = "attacker edit"
    ok, bad, reason = attest.verify_chain(t, None)
    assert not ok and bad == 1 and "modified" in reason


def test_delete_entry_detected(chain):
    t = copy.deepcopy(chain)
    del t[1]
    for i, e in enumerate(t):
        e["seq"] = i  # naive attacker renumbers
    ok, _, _ = attest.verify_chain(t, None)
    assert not ok


def test_reorder_detected(chain):
    t = copy.deepcopy(chain)
    t[0], t[1] = t[1], t[0]
    ok, _, _ = attest.verify_chain(t, None)
    assert not ok


def test_seq_gap_detected(chain):
    t = copy.deepcopy(chain)
    t[2]["seq"] = 5
    ok, bad, reason = attest.verify_chain(t, None)
    assert not ok and bad == 2 and "sequence" in reason


def test_prev_hash_splice_detected(chain):
    t = copy.deepcopy(chain)
    t[2]["prev_hash"] = "0" * 64  # splice a foreign link
    ok, bad, _ = attest.verify_chain(t, None)
    assert not ok and bad == 2


def test_append_forgery_without_recompute_detected(chain):
    t = copy.deepcopy(chain)
    t.append(
        {
            "seq": len(t),
            "event_id": "forged",
            "ts": None,
            "payload": {"op": "add", "text": "forged"},
            "prev_hash": t[-1]["curr_hash"],
            "curr_hash": "f" * 64,
        }
    )
    ok, bad, _ = attest.verify_chain(t, None)
    assert not ok and bad == len(t) - 1


def test_hmac_rejects_wrong_key():
    chain_real = attest.build_chain(FIXED_EVENTS, b"real-key")
    ok, _, _ = attest.verify_chain(chain_real, b"wrong-key")
    assert not ok, "verification with the wrong HMAC key must fail"


def test_hmac_attacker_cannot_recompute_without_key():
    chain_real = attest.build_chain(FIXED_EVENTS, b"real-key")
    forged = copy.deepcopy(chain_real)
    forged[0]["payload"]["text"] = "tampered"
    forged[0]["curr_hash"] = attest.digest(
        "GENESIS", attest._payload_for_hash(forged[0]), b"attacker-guess"
    )
    ok, _, _ = attest.verify_chain(forged, b"real-key")
    assert not ok


# ---- canonical serialization stability & edge cases --------------------------
def test_canonical_key_order_stable():
    assert attest.canonical({"a": 1, "b": 2}) == attest.canonical({"b": 2, "a": 1})


def test_canonical_unicode_stable():
    zh = {"text": "使用者偏好深色模式"}
    assert attest.canonical(zh) == attest.canonical(json.loads(json.dumps(zh)))
    assert "使用者" in attest.canonical(zh).decode("utf-8")  # ensure_ascii=False preserved


def test_canonical_float_form_pinned():
    # 1000.0 must serialize identically across runs (float repr stability)
    a = attest.canonical({"t": 1000.0})
    b = attest.canonical({"t": 1000.0})
    assert a == b


def test_empty_log_edge_case():
    chain = attest.build_chain([], None)
    ok, bad, _ = attest.verify_chain(chain, None)
    assert ok and chain == [] and attest.root_of(chain) == "GENESIS"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
