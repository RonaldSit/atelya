"""Unit tests for amem_governance.py — audit / lineage / conflicts / GDPR erase /
retention / summary / CLI, pinned to the shipped semantics (no aspirational asserts).

Run:  pytest tests/test_amem_governance.py -v
"""

import copy
import importlib.util
import json
import os
import sys

import pytest

# ---- load the exact shipped modules by path (works regardless of cwd) -----------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # so governance's lazy `import amem_attest` resolves
    spec.loader.exec_module(mod)
    return mod


attest = _load("amem_attest")
gov = _load("amem_governance")

# ---- shared fixture: one op-log exercising every lifecycle path ------------------
BASE = [
    {
        "op": "add",
        "id": "a",
        "text": "user works at Boeing",
        "key": "employer",
        "created_at": 1000.0,
    },
    {
        "op": "add",
        "id": "b",
        "text": "user works at Airbus",
        "key": "employer",
        "created_at": 2000.0,
    },
    {"op": "update", "id": "b", "text": "user works at Airbus (verified)", "created_at": 3000.0},
    {
        "op": "add",
        "id": "c",
        "text": "allergic to penicillin",
        "key": "allergy",
        "created_at": 4000.0,
        "actor": "nurse",
    },
    {"op": "flag", "a": "a", "b": "b", "why": "employer conflict", "created_at": 4500.0},
    {"op": "forget", "id": "c", "created_at": 5000.0},
]


def write_log(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return str(path)


@pytest.fixture()
def logfile(tmp_path):
    return write_log(tmp_path / "ops.jsonl", copy.deepcopy(BASE))


# ================================ read_log ========================================
def test_read_log_skips_malformed_and_blank(tmp_path):
    p = tmp_path / "ops.jsonl"
    p.write_text('{"op":"add","id":"x","text":"ok"}\n\n{{{not json\n', encoding="utf-8")
    evs = gov.read_log(str(p))
    assert len(evs) == 1 and evs[0]["id"] == "x"


def test_read_log_legacy_text_promoted_to_add(tmp_path):
    p = tmp_path / "ops.jsonl"
    p.write_text('{"text":"legacy fact","id":"z"}\n', encoding="utf-8")
    (ev,) = gov.read_log(str(p))
    assert ev["op"] == "add" and ev["text"] == "legacy fact" and ev["id"] == "z"


# ================================ replay ==========================================
def test_replay_same_key_supersede():
    rec, order = gov.replay(copy.deepcopy(BASE))
    assert rec["a"]["status"] == "superseded"
    assert "superseded-by-b" in rec["a"]["history"]
    assert rec["b"]["status"] == "active"
    assert order == ["a", "b", "c"]


def test_replay_update_and_forget():
    rec, _ = gov.replay(copy.deepcopy(BASE))
    assert rec["b"]["text"].endswith("(verified)") and "update" in rec["b"]["history"]
    assert rec["c"]["status"] == "deleted" and "forget" in rec["c"]["history"]


def test_replay_purge_redacts_and_autoid():
    evs = copy.deepcopy(BASE) + [
        {"op": "purge", "id": "b", "created_at": 6000.0},
        {"op": "add", "text": "no id given"},
    ]
    rec, order = gov.replay(evs)
    assert rec["b"]["status"] == "purged" and rec["b"]["text"] == "<redacted>"
    auto = [r for r in order if str(r).startswith("_auto")]
    assert len(auto) == 1 and rec[auto[0]]["text"] == "no id given"


# ============================ audit_timeline / export =============================
def test_audit_timeline_rows_and_flag_detail():
    rows = gov.audit_timeline(copy.deepcopy(BASE))
    assert len(rows) == len(BASE)
    assert [r["seq"] for r in rows] == list(range(len(BASE)))
    flag = rows[4]
    assert flag["op"] == "flag" and flag["id"] == "a"
    assert "contradiction a=a b=b" in flag["detail"]
    t = rows[0]["time"]  # created_at=1000.0 renders as a timestamp;
    assert (
        len(t) == 19 and t[4] == "-" and t[10] == "T"
    )  # tz-agnostic (local year may be 1969/1970)


def test_export_json_roundtrip(tmp_path):
    rows = gov.audit_timeline(copy.deepcopy(BASE))
    out, fmt = gov.export(rows, str(tmp_path / "audit.json"))
    assert fmt == "json"
    data = json.loads(open(out, encoding="utf-8").read())
    assert isinstance(data, list) and len(data) == len(rows)


def test_export_csv_header_and_rows(tmp_path):
    rows = gov.audit_timeline(copy.deepcopy(BASE))
    out, fmt = gov.export(rows, str(tmp_path / "audit.csv"))
    lines = open(out, encoding="utf-8").read().strip().splitlines()
    assert fmt == "csv"
    assert lines[0] == "seq,time,op,id,actor,detail"
    assert len(lines) == 1 + len(rows)


# ============================== lineage / conflicts ================================
def test_lineage_tracks_id_and_flag_edges():
    evs = copy.deepcopy(BASE)
    ops_a = [op for _, op, _ in gov.lineage(evs, "a")]
    ops_b = [op for _, op, _ in gov.lineage(evs, "b")]
    assert ops_a == ["add", "flag"]  # flag references a via the `a` edge
    assert ops_b == ["add", "update", "flag"]


def test_conflicts_winner_is_active_side():
    (c,) = gov.conflicts(copy.deepcopy(BASE))
    assert (c["a_status"], c["b_status"]) == ("superseded", "active")
    assert c["winner"] == "b" and c["why"] == "employer conflict"


def test_conflicts_unresolved_when_both_active():
    evs = [
        {"op": "add", "id": "x", "text": "likes tea", "key": "k1", "created_at": 1.0},
        {"op": "add", "id": "y", "text": "likes coffee", "key": "k2", "created_at": 2.0},
        {"op": "flag", "a": "x", "b": "y", "why": "beverage"},
    ]
    (c,) = gov.conflicts(evs)
    assert c["winner"] == "unresolved"


# ============================== GDPR erase ========================================
def test_erase_soft_appends_forget_and_retains_text(logfile):
    r = gov.erase(logfile, "Airbus", hard=False)
    assert r == {"matched": 1, "mode": "soft", "ids": ["b"]}
    evs = gov.read_log(logfile)
    assert len(evs) == len(BASE) + 1  # forget appended, nothing removed
    assert evs[-1]["op"] == "forget" and evs[-1]["id"] == "b"
    assert evs[-1]["reason"] == "erasure:/Airbus/"
    assert any("Airbus" in (e.get("text") or "") for e in evs)  # auditable: text retained
    rec, _ = gov.replay(evs)
    assert rec["b"]["status"] == "deleted"


def test_erase_soft_no_match_leaves_log_untouched(logfile):
    before = open(logfile, encoding="utf-8").read()
    r = gov.erase(logfile, "zzz-no-such", hard=False)
    assert r["matched"] == 0
    assert open(logfile, encoding="utf-8").read() == before


def test_erase_hard_removes_content_logs_purge_and_resurrects_predecessor(logfile):
    r = gov.erase(logfile, "Airbus", hard=True)
    assert r["matched"] == 1 and r["mode"] == "hard" and r["ids"] == ["b"]
    evs = gov.read_log(logfile)
    assert not any("Airbus" in (e.get("text") or "") for e in evs)  # content truly gone
    # dropped: add b, update b, and the flag row (it references b) -> 3 kept + 1 purge marker
    assert len(evs) == 4
    purge = evs[-1]
    assert purge["op"] == "purge" and purge["id"] == "b"
    assert purge["note"] == "content removed for compliance"  # the purge itself is logged
    # honest note: the marker's reason records the erasure *pattern* verbatim — erase by
    # label/id-pattern, not by pasting the literal secret (0.2: consider hashing it)
    assert purge["reason"] == "erasure:/Airbus/"
    assert not any(e.get("op") == "flag" for e in evs)  # erase-hard drops referencing flags
    rec, _ = gov.replay(evs)
    assert "b" not in rec  # purge marker alone creates no record
    # documented quirk: with the superseding add gone, the predecessor is active again
    assert rec["a"]["status"] == "active"


# ================================ retention =======================================
def test_retention_age_soft_retires_stale_active(logfile):
    r = gov.retention(logfile, max_age_days=1, hard=False)  # created_at epoch-1970 => stale
    assert r["retired"] == 1 and r["ids"] == ["b"] and r["mode"] == "soft"
    rec, _ = gov.replay(gov.read_log(logfile))
    assert rec["b"]["status"] == "deleted"  # only active records are retired


def test_retention_max_active_retires_oldest_first(tmp_path):
    evs = [
        {"op": "add", "id": f"m{i}", "text": f"t{i}", "key": f"k{i}", "created_at": float(i)}
        for i in (1, 2, 3)
    ]
    p = write_log(tmp_path / "ops.jsonl", evs)
    r = gov.retention(p, max_active=1, hard=False)
    assert r["retired"] == 2 and r["ids"] == ["m1", "m2"]  # oldest first
    rec, _ = gov.replay(gov.read_log(p))
    assert rec["m3"]["status"] == "active"


def test_retention_hard_rewrites_but_keeps_flag_rows(logfile):
    r = gov.retention(logfile, max_age_days=1, hard=True)
    assert r["retired"] == 1 and r["mode"] == "hard"
    raw = open(logfile, encoding="utf-8").read()
    assert "Airbus" not in raw
    evs = gov.read_log(logfile)
    assert any(e.get("op") == "purge" and e.get("reason") == "retention" for e in evs)
    # asymmetry vs erase-hard: retention filters by id only, so the flag row survives
    assert any(e.get("op") == "flag" for e in evs)


# ================================= summary ========================================
def test_summary_counts_and_actor_tracking():
    s = gov.summary(copy.deepcopy(BASE))
    assert s["events"] == 6 and s["memories"] == 3
    assert s["by_status"] == {"superseded": 1, "active": 1, "deleted": 1}
    assert s["contradiction_flags"] == 1
    assert s["actor_tracking"] == "present"  # c carries actor="nurse"


# ================================== CLI ===========================================
def test_cli_guard_exits(logfile):
    with pytest.raises(SystemExit):
        gov.main([])  # usage
    with pytest.raises(SystemExit):
        gov.main(["lineage", logfile])  # --id required
    with pytest.raises(SystemExit):
        gov.main(["audit", logfile + ".nope"])  # op-log not found


def test_cli_audit_export_rc0(logfile, tmp_path, capsys):
    out = str(tmp_path / "audit.json")
    rv = gov.main(["audit", logfile, "--out", out])
    assert rv == 0 and os.path.exists(out)
    assert "exported 6 events" in capsys.readouterr().out


def test_cli_attest_verify_roundtrip_and_tamper_exit(logfile, tmp_path, capsys):
    chain = str(tmp_path / "chain.jsonl")
    rv = gov.main(["attest", logfile, "--out", chain])
    assert rv in (0, None) and os.path.exists(chain)
    rv = gov.main(["verify-chain", chain])
    assert rv in (0, None)
    assert "VERIFIED" in capsys.readouterr().out
    tampered = open(chain, encoding="utf-8").read().replace("Boeing", "BoeinX")
    open(chain, "w", encoding="utf-8").write(tampered)
    with pytest.raises(SystemExit) as e:
        gov.main(["verify-chain", chain])
    assert "TAMPER DETECTED" in str(e.value)


def test_module_selftest_passes(capsys):
    assert gov._selftest() == 0
    assert "SELFTEST PASS" in capsys.readouterr().out


def test_cli_erase_rejects_invalid_regex(logfile):
    with pytest.raises(SystemExit) as e:
        gov.main(["erase", logfile, "--match", "["])
    assert "invalid --match regex" in str(e.value)
