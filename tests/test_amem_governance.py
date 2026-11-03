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
    # the marker's reason is a SHA-256 digest of the pattern — verifiable, never leaks it
    import hashlib as _h

    assert purge["reason"] == "erasure:sha256:" + _h.sha256(b"Airbus").hexdigest()
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


def test_key_loaders_reject_whitespace_only_inline():
    import types

    with pytest.raises(SystemExit):
        attest._load_key(types.SimpleNamespace(key="   ", keyfile=None))
    anchor = _load("amem_anchor")
    with pytest.raises(SystemExit):
        anchor._load_key("   ", None, "AMEM_ANCHOR_KEY")


def test_anchor_check_forgotten_label_fails_loudly(tmp_path):
    import contextlib
    import io

    anchor = _load("amem_anchor")
    log = tmp_path / "l.jsonl"
    log.write_text('{"op":"add","id":"m1","text":"secret","created_at":1.0}\n')
    ch = tmp_path / "ch.jsonl"
    led = tmp_path / "led.jsonl"
    with contextlib.redirect_stdout(io.StringIO()):
        attest.main(["attest", str(log), "--out", str(ch)])
        anchor.main(["anchor", str(ch), "--ledger", str(led), "--label", "demo"])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = anchor.main(["check", str(ch), "--ledger", str(led)])  # forgot --label
    assert rc == 1 and "demo" in buf.getvalue()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = anchor.main(["check", str(ch), "--ledger", str(led), "--label", "demo"])
    assert rc == 0 and "VERIFIED" in buf.getvalue()


# =========================== post-purge hooks =====================================
def _recorder(calls, fail=False):
    def hook(oplog_path, purged, match):
        calls.append((oplog_path, purged, match))
        if fail:
            raise RuntimeError("cannot reach the session store")
        return {"removed": len(purged)}

    return hook


def _sha(text):
    import hashlib as _h

    return _h.sha256(text.encode("utf-8")).hexdigest()


def test_purge_hook_gets_ids_digests_and_matcher_never_the_text(logfile, monkeypatch):
    calls = []
    monkeypatch.setattr(gov, "_purge_hooks", lambda: [("rec", _recorder(calls))])
    r = gov.erase(logfile, "Airbus", hard=True)
    assert r["hooks"] == [{"hook": "rec", "ok": True, "result": {"removed": 1}}]
    ((path, purged, match),) = calls
    assert path == logfile
    # every text the record ever had (add + update), as digests only
    assert purged == {"b": [_sha("user works at Airbus"), _sha("user works at Airbus (verified)")]}
    assert match("a note about AIRBUS") and not match("user works at Boeing")  # same regex, re.I
    flat = json.dumps([path, purged])
    assert "Airbus" not in flat and "airbus" not in flat.lower()  # never the erased text


def test_purge_hooks_discovered_from_entry_points(monkeypatch):
    import importlib.metadata as md

    class EP:
        def __init__(self, name, fn=None, err=None):
            self.name, self._fn, self._err = name, fn, err

        def load(self):
            if self._err:
                raise self._err
            return self._fn

    good = _recorder([])
    seen = {}

    def fake_entry_points(group=None):
        seen["group"] = group
        return [EP("zeta", good), EP("alpha", err=ImportError("no module named x"))]

    monkeypatch.setattr(md, "entry_points", fake_entry_points)
    hooks = gov._purge_hooks()
    assert seen["group"] == "atelya.purge_hooks"
    assert [n for n, _ in hooks] == ["alpha", "zeta"]  # sorted, deterministic
    assert isinstance(hooks[0][1], ImportError) and hooks[1][1] is good
    res = gov.run_purge_hooks("x.jsonl", {}, None)
    assert res[0]["hook"] == "alpha" and res[0]["ok"] is False and "ImportError" in res[0]["error"]
    assert res[1] == {"hook": "zeta", "ok": True, "result": {"removed": 0}}


def test_cli_hard_erase_says_when_no_hook_is_installed(logfile, monkeypatch, capsys):
    monkeypatch.setattr(gov, "_purge_hooks", lambda: [])
    assert gov.main(["erase", logfile, "--match", "Airbus", "--hard"]) == 0
    out = capsys.readouterr().out
    assert "post-purge hooks: none installed" in out and "atelya.purge_hooks" in out


def test_cli_prints_every_hook_outcome_and_fails_if_one_failed(logfile, monkeypatch, capsys):
    monkeypatch.setattr(
        gov, "_purge_hooks", lambda: [("good", _recorder([])), ("bad", _recorder([], fail=True))]
    )
    assert gov.main(["erase", logfile, "--match", "Airbus", "--hard"]) == 1
    out = capsys.readouterr().out
    assert 'post-purge hook good: ok {"removed": 1}' in out
    assert "post-purge hook bad: FAILED RuntimeError: cannot reach the session store" in out
    assert "ERASE INCOMPLETE: 1 post-purge hook(s) failed" in out


def test_cli_soft_erase_says_hooks_not_run(logfile, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(gov, "_purge_hooks", lambda: [("rec", _recorder(calls))])
    assert gov.main(["erase", logfile, "--match", "Airbus"]) == 0
    assert calls == []
    assert "post-purge hooks: not run (soft mode" in capsys.readouterr().out


def test_hard_erase_rerun_with_no_match_still_runs_hooks(logfile, monkeypatch):
    calls = []
    monkeypatch.setattr(gov, "_purge_hooks", lambda: [("rec", _recorder(calls))])
    gov.erase(logfile, "Airbus", hard=True)
    r = gov.erase(logfile, "Airbus", hard=True)  # already purged: matches nothing
    assert r["matched"] == 0 and len(calls) == 2
    _, purged, match = calls[1]
    assert purged == {} and match("Airbus")  # the hook can still clean up by pattern


def test_retention_hard_runs_hooks_without_a_matcher(logfile, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(gov, "_purge_hooks", lambda: [("rec", _recorder(calls))])
    assert gov.main(["retention", logfile, "--max-age-days", "1", "--hard"]) == 0
    ((_, purged, match),) = calls
    assert set(purged) == {"b"} and match is None
    assert "post-purge hook rec: ok" in capsys.readouterr().out


@pytest.mark.parametrize("hard", [False, True])
def test_cli_erase_no_match_says_so_and_changes_nothing(logfile, monkeypatch, capsys, hard):
    monkeypatch.setattr(gov, "_purge_hooks", lambda: [])
    before = open(logfile, "rb").read()
    argv = ["erase", logfile, "--match", "zz-no-such-text-zz"] + (["--hard"] if hard else [])
    assert gov.main(argv) == 0
    out = capsys.readouterr().out
    assert "NO MATCH: no record matched --match" in out
    assert "content removed" not in out and "HARD PURGE" not in out and "SOFT forget" not in out
    assert "were purged" not in out  # the no-hook line must not claim a purge either
    assert "zz-no-such-text-zz" not in out  # the pattern may be the very text to erase
    assert open(logfile, "rb").read() == before


@pytest.mark.parametrize(
    "hard,verdict", [(True, "HARD PURGE (content removed)"), (False, "SOFT forget")]
)
def test_cli_erase_with_a_match_keeps_its_verdict(logfile, monkeypatch, capsys, hard, verdict):
    monkeypatch.setattr(gov, "_purge_hooks", lambda: [])
    gov.main(["erase", logfile, "--match", "Airbus"] + (["--hard"] if hard else []))
    out = capsys.readouterr().out
    assert verdict in out and "NO MATCH" not in out


def test_cli_retention_with_nothing_due_says_nothing_was_purged(logfile, monkeypatch, capsys):
    monkeypatch.setattr(gov, "_purge_hooks", lambda: [])
    argv = ["retention", logfile, "--max-age-days", "100000", "--hard"]
    assert gov.main(argv) == 0
    out = capsys.readouterr().out
    assert '"retired": 0' in out
    assert "nothing was purged" in out and "were purged" not in out
