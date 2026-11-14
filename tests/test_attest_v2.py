"""Attest v2: a hash-only chain over the op-log (atelya web3-features-spec W3).

Entry: {"v": 2, "seq": n, "line_sha256" | "line_hmac" + "keyed": true, "prev"}, no payload.
A line that names its record by a uuid4 (122 random bits) gets a plain sha256 of its
exact bytes; any other line (every id atelya writes today has 48 bits) gets an
HMAC-SHA256 with <data_dir>/.erasure_key, so its content cannot be confirmed by
guessing. A hard purge appends a redaction record {"v": 2, "redact": [seq...],
"purge_marker": id, "prev"} instead of needing --drop-attest; v1 chains keep the
refusal. Verification recomputes every line from the op-log and names the first
problem: modified, reordered, inserted or missing line, a redaction naming a line
that still exists, a broken link, a missing key.

This file is identical in atelya and atelya-public. Temp dirs, neutral markers.
Run:  pytest tests/test_attest_v2.py -q
"""

import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


attest = _load("amem_attest")
gov = _load("amem_governance")

UUID4_ID = "5f0c2b1e9a3d4c7e8b6a1f2d3c4b5a69"  # a uuid4 in hex: version 4, variant 8..b
assert UUID4_ID[12] == "4" and UUID4_ID[16] in "89ab"
TEXTS = {
    "a1": "neutral alpha note about the blue planter",
    "a2": "neutral beta note about the green door",
    "a3": "中性備註:備用鑰匙在藍色花盆下面,請勿外傳",
    UUID4_ID: "neutral gamma note with a long random id",
}


def _need(mod, name):
    assert hasattr(mod, name), f"{mod.__name__}.{name} is missing (attest v2 not implemented)"
    return getattr(mod, name)


def ev_add(rid, t):
    return {
        "op": "add",
        "id": rid,
        "text": TEXTS[rid],
        "key": None,
        "created_at": t,
        "ts": f"1970-01-01T00:00:{int(t):02d}.000000Z",
        "v": 2,
    }


def write_oplog(d, extra=()):
    p = os.path.join(str(d), "user.jsonl")
    evs = [ev_add("a1", 1), ev_add("a2", 2), ev_add("a3", 3), ev_add(UUID4_ID, 4)]
    evs += [
        {
            "op": "flag",
            "a": "a1",
            "b": "a2",
            "why": "numeric_mismatch",
            "ts": "1970-01-01T00:00:05.000000Z",
            "v": 2,
        }
    ]
    evs += list(extra)
    with open(p, "w", encoding="utf-8", newline="") as f:
        for e in evs:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return p


def raw_lines(p):
    with open(p, "rb") as f:
        return [x for x in f.read().split(b"\n") if x.strip()]


def write_raw(p, lines):
    with open(p, "wb") as f:
        f.write(b"".join(x + b"\n" for x in lines))


def chain_of(p):
    with open(p + ".attest.jsonl", encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def key_of(p):
    with open(os.path.join(os.path.dirname(p), ".erasure_key"), "rb") as f:
        return f.read()


def verify(p):
    return _need(gov, "verify_v2")(p + ".attest.jsonl", p)


def attest_v2(p):
    return _need(gov, "attest_v2")(p)


def _cli(*argv):
    return subprocess.run(
        [sys.executable, os.path.join(_ROOT, "amem_governance.py"), *argv],
        capture_output=True,
        text=True,
        timeout=60,
    )


# ================================ format ===========================================
def test_entry_format_and_links(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    chain = chain_of(p)
    assert [e["seq"] for e in chain] == [0, 1, 2, 3, 4]
    for e in chain:
        assert e["v"] == 2 and type(e["v"]) is int
        assert set(e) in (
            {"v", "seq", "line_sha256", "prev"},
            {"v", "seq", "line_hmac", "keyed", "prev"},
        ), e
    assert chain[0]["prev"] == "GENESIS"
    for i in range(1, len(chain)):
        assert chain[i]["prev"] == hashlib.sha256(attest.canonical(chain[i - 1])).hexdigest()


def test_head_is_the_sha256_of_the_last_entry(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    chain = chain_of(p)
    head = _need(attest, "chain_head_v2")(chain)
    assert head == hashlib.sha256(attest.canonical(chain[-1])).hexdigest()
    assert verify(p)["head"] == head


def test_a_uuid4_line_is_a_plain_sha256_and_any_other_line_is_keyed(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    chain, raws, key = chain_of(p), raw_lines(p), key_of(p)
    assert len(key) == 32
    if os.name == "posix":
        assert os.stat(os.path.join(str(tmp_path), ".erasure_key")).st_mode & 0o777 == 0o600
    assert len(chain) == len(raws)
    for e, raw in ((chain[i], raws[i]) for i in range(len(raws))):
        ev = json.loads(raw)
        if ev.get("id") == UUID4_ID:
            assert e == {
                "v": 2,
                "seq": e["seq"],
                "line_sha256": hashlib.sha256(raw).hexdigest(),
                "prev": e["prev"],
            }
        else:
            want = hmac.new(key, raw, hashlib.sha256).hexdigest()
            assert e == {
                "v": 2,
                "seq": e["seq"],
                "line_hmac": want,
                "keyed": True,
                "prev": e["prev"],
            }


@pytest.mark.parametrize(
    "rid,plain",
    [
        (UUID4_ID, True),
        ("5f0c2b1e9a3d", False),  # 12 hex: what atelya writes today (48 bits)
        ("5f0c2b1e9a3d3c7e8b6a1f2d3c4b5a69", False),  # 32 hex, version nibble 3
        ("5f0c2b1e9a3d4c7e7b6a1f2d3c4b5a69", False),  # variant nibble 7
        ("5F0C2B1E9A3D4C7E8B6A1F2D3C4B5A69", False),  # upper case: not what uuid4().hex gives
        (None, False),
    ],
)
def test_only_a_uuid4_id_counts_as_unguessable(rid, plain):
    assert _need(attest, "unguessable")({"op": "add", "id": rid, "text": "x"}) is plain


def test_the_chain_carries_no_text(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    data = open(p + ".attest.jsonl", encoding="utf-8").read()
    for t in TEXTS.values():
        for form in (t, json.dumps(t)[1:-1], json.dumps(t, ensure_ascii=False)[1:-1]):
            for i in range(0, max(1, len(form) - 19)):
                assert form[i : i + 20] not in data, form[i : i + 20]


# ================================ verification =====================================
def test_an_untouched_oplog_verifies(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    r = verify(p)
    assert r["ok"] and r["verified"] == 5 and r["unattested"] == 0 and r["redacted"] == 0, r
    out = _cli("verify-chain", p + ".attest.jsonl")
    assert out.returncode == 0 and "VERIFIED" in out.stdout, out.stdout + out.stderr


def _fail(p, kind, seq=None):
    r = verify(p)
    assert not r["ok"] and r["error"]["kind"] == kind, r
    if seq is not None:
        assert r["error"]["seq"] == seq, r
    out = _cli("verify-chain", p + ".attest.jsonl")
    assert out.returncode != 0 and kind in (out.stdout + out.stderr), out.stdout + out.stderr
    return r


def test_detects_a_modified_line(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    raws = raw_lines(p)
    raws[1] = raws[1].replace(b"green door", b"green gate")
    write_raw(p, raws)
    _fail(p, "modified_line", 1)


def test_detects_reordered_lines(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    raws = raw_lines(p)
    raws[1], raws[2] = raws[2], raws[1]
    write_raw(p, raws)
    _fail(p, "reordered", 1)


def test_detects_an_inserted_line(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    raws = raw_lines(p)
    raws.insert(
        2,
        json.dumps(
            {"op": "forget", "id": "a1", "ts": "1970-01-01T00:00:09.000000Z", "v": 2}
        ).encode(),
    )
    write_raw(p, raws)
    _fail(p, "inserted_line", 2)


def test_detects_a_line_deleted_without_a_redaction(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    raws = raw_lines(p)
    del raws[2]
    write_raw(p, raws)
    _fail(p, "missing_line", 2)


def test_detects_a_redaction_that_names_a_line_still_there(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    chain = chain_of(p)
    chain.append(_need(attest, "redaction_v2")(chain, [1], "a2"))
    with open(p + ".attest.jsonl", "w", encoding="utf-8") as f:
        for e in chain:
            f.write(json.dumps(e) + "\n")
    _fail(p, "redacted_line_present", 1)


def test_detects_a_broken_link(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    chain = chain_of(p)
    chain[2]["line_hmac"] = "0" * 64
    with open(p + ".attest.jsonl", "w", encoding="utf-8") as f:
        for e in chain:
            f.write(json.dumps(e) + "\n")
    _fail(p, "broken_link", 3)


def test_a_redaction_must_come_after_the_line_it_covers(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    raws = raw_lines(p)
    chain = chain_of(p)[:2]  # seq 0 and 1, then a redaction naming seq 2 (not yet chained)
    chain.append(attest.redaction_v2(chain, [2], "a3"))
    chain = attest.extend_chain_v2(chain, [(r, json.loads(r)) for r in raws[2:]], key_of(p))
    with open(p + ".attest.jsonl", "w", encoding="utf-8") as f:
        for e in chain:
            f.write(json.dumps(e) + "\n")
    del raws[2]
    write_raw(p, raws)
    _fail(p, "redaction_before_line")


def test_keyed_entries_need_the_key(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    os.remove(os.path.join(str(tmp_path), ".erasure_key"))
    _fail(p, "key_missing")
    assert not os.path.exists(
        os.path.join(str(tmp_path), ".erasure_key")
    )  # verify never creates it


def test_lines_appended_after_the_chain_are_reported_as_unattested(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    with open(p, "a", encoding="utf-8") as f:
        f.write(
            json.dumps({"op": "forget", "id": "a2", "ts": "1970-01-01T00:00:09.000000Z", "v": 2})
            + "\n"
        )
    r = verify(p)
    assert r["ok"] and r["verified"] == 5 and r["unattested"] == 1, r


def test_attest_again_extends_the_chain_and_keeps_what_was_there(tmp_path):
    p = write_oplog(tmp_path)
    r1 = attest_v2(p)
    before = open(p + ".attest.jsonl", "rb").read()
    with open(p, "a", encoding="utf-8") as f:
        f.write(
            json.dumps({"op": "forget", "id": "a2", "ts": "1970-01-01T00:00:09.000000Z", "v": 2})
            + "\n"
        )
    r2 = attest_v2(p)
    after = open(p + ".attest.jsonl", "rb").read()
    assert after.startswith(before) and after != before
    assert r2["appended"] == 1 and r2["last_seq"] == 5 and r2["head"] != r1["head"], (r1, r2)
    assert verify(p)["ok"] and verify(p)["unattested"] == 0


def test_attest_refuses_to_extend_a_chain_that_no_longer_matches(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    raws = raw_lines(p)
    raws[0] = raws[0].replace(b"blue planter", b"blue planters")
    write_raw(p, raws)
    before = open(p + ".attest.jsonl", "rb").read()
    with pytest.raises(ValueError, match="modified_line"):
        attest_v2(p)
    assert open(p + ".attest.jsonl", "rb").read() == before


# ================================ hard purge =======================================
def test_hard_erase_appends_a_redaction_and_still_verifies(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    out = gov.erase(p, "green door", hard=True)
    assert out["matched"] == 1 and out.get("attest_redacted") == [1, 4], out
    chain = chain_of(p)
    red = chain[-1]
    assert set(red) == {"v", "redact", "purge_marker", "prev"}, red
    assert red["v"] == 2 and red["redact"] == [1, 4] and red["purge_marker"] == "a2"
    assert red["prev"] == hashlib.sha256(attest.canonical(chain[-2])).hexdigest()
    r = verify(p)
    assert r["ok"] and r["redacted"] == 2 and r["unattested"] == 1, r  # the purge marker line
    data = open(p + ".attest.jsonl", encoding="utf-8").read() + open(p, encoding="utf-8").read()
    assert TEXTS["a2"] not in data


def test_hard_retention_redacts_per_purged_record(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    out = gov.retention(p, max_active=2, hard=True)
    assert out["retired"] == 2, out
    reds = [e for e in chain_of(p) if "redact" in e]
    assert sorted((e["purge_marker"], e["redact"]) for e in reds) == [
        ("a1", [0, 4]),
        ("a2", [1, 4]),
    ], reds
    assert verify(p)["ok"]


def test_purging_lines_that_were_never_attested_writes_no_redaction(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    with open(p, "a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "op": "add",
                    "id": "a9",
                    "text": "neutral late note zq",
                    "key": None,
                    "v": 2,
                    "ts": "1970-01-01T00:00:09.000000Z",
                }
            )
            + "\n"
        )
    n = len(chain_of(p))
    out = gov.erase(p, "late note zq", hard=True)
    assert out["matched"] == 1 and out.get("attest_redacted") == [], out
    assert len(chain_of(p)) == n and verify(p)["ok"]


def test_hard_purge_refuses_while_the_v2_chain_does_not_match(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    raws = raw_lines(p)
    raws[3] = raws[3].replace(b"gamma", b"delta")
    write_raw(p, raws)
    before = (open(p, "rb").read(), open(p + ".attest.jsonl", "rb").read())
    with pytest.raises(ValueError, match="modified_line"):
        gov.erase(p, "green door", hard=True)
    assert (open(p, "rb").read(), open(p + ".attest.jsonl", "rb").read()) == before


def test_a_v1_chain_keeps_the_refusal(tmp_path):
    p = write_oplog(tmp_path)
    assert _cli("attest", p).returncode == 0  # v1, the default
    with pytest.raises(ValueError, match="--drop-attest"):
        gov.erase(p, "green door", hard=True)


# ================================ v1 and v2 side by side ===========================
def test_v1_attest_refuses_to_overwrite_a_v2_chain(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    before = open(p + ".attest.jsonl", "rb").read()
    out = _cli("attest", p)
    assert out.returncode != 0 and "v2" in out.stderr, out.stdout + out.stderr
    assert open(p + ".attest.jsonl", "rb").read() == before


def test_v2_attest_refuses_an_existing_v1_chain(tmp_path):
    p = write_oplog(tmp_path)
    assert _cli("attest", p).returncode == 0
    before = open(p + ".attest.jsonl", "rb").read()
    out = _cli("attest", p, "--v2")
    assert out.returncode != 0 and "v1" in out.stderr, out.stdout + out.stderr
    assert open(p + ".attest.jsonl", "rb").read() == before


def test_verify_chain_reads_v1_and_v2(tmp_path):
    d1, d2 = tmp_path / "v1", tmp_path / "v2"
    d1.mkdir()
    d2.mkdir()
    q1, q2 = write_oplog(d1), write_oplog(d2)
    assert _cli("attest", q1).returncode == 0
    assert _cli("attest", q2, "--v2").returncode == 0
    for q in (q1, q2):
        out = _cli("verify-chain", q + ".attest.jsonl")
        assert out.returncode == 0 and "VERIFIED" in out.stdout, out.stdout + out.stderr
    out = _cli("verify-chain", os.path.join(str(d2), "elsewhere.jsonl"), "--oplog", q2)
    assert out.returncode != 0


def test_verify_chain_takes_the_oplog_from_an_option(tmp_path):
    p = write_oplog(tmp_path)
    out_chain = os.path.join(str(tmp_path), "kept-elsewhere.jsonl")
    assert _cli("attest", p, "--v2", "--out", out_chain).returncode == 0
    out = _cli("verify-chain", out_chain, "--oplog", p)
    assert out.returncode == 0 and "VERIFIED" in out.stdout, out.stdout + out.stderr


def test_the_standalone_attest_cli_points_a_v2_chain_to_atelya_govern(tmp_path):
    p = write_oplog(tmp_path)
    attest_v2(p)
    out = subprocess.run(
        [sys.executable, os.path.join(_ROOT, "amem_attest.py"), "verify", p + ".attest.jsonl"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode != 0 and "verify-chain" in (out.stdout + out.stderr), (
        out.stdout + out.stderr
    )
