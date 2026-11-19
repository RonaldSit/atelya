"""atelya-govern provenance: who wrote a record, when, through which channel, and what retired it,
without its text (atelya web3-goal-spec B1, step 4).

`provenance <oplog> --id <rid>` prints one JSON line per event that concerns the record, in op-log
order: its add and updates (seq, ts, trust, path, author as an HMAC with <data_dir>/.erasure_key),
the records its keyed add retired, what retired it (an explicit supersede, or a later keyed add,
which retires the holders of its key without a supersede line: the writer's src, the time, the
retiring record), quarantine and release, forget. Never text, slot keys or plain authors; it never
creates the key, and it only reads: on a torn last line it refuses and names the repair command.

This file is identical in atelya and atelya-public. Temp dirs, neutral markers.
Run:  pytest tests/test_govern_provenance.py -q
"""

import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
GOVERN = os.path.join(_ROOT, "amem_governance.py")

AUTHOR = "zq-feed-4471"
TS = ["2026-11-18T10:00:0%d.000000Z" % i for i in range(10)]
KEY = bytes(range(32))


def _line(**ev):
    return json.dumps(dict(ev, v=2))


def _store(tmp_path, lines, key=True):
    d = tmp_path / "data"
    d.mkdir()
    if key:
        (d / ".erasure_key").write_bytes(KEY)
    p = d / "user_test.jsonl"
    p.write_text("".join(x + "\n" for x in lines), encoding="utf-8")
    return p


def _run(path, rid):
    r = subprocess.run(
        [
            sys.executable,
            os.path.join(_ROOT, "amem_governance.py"),
            "provenance",
            str(path),
            "--id",
            rid,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return r, [json.loads(x) for x in r.stdout.splitlines() if x.startswith("{")]


def _hmac(s):
    return hmac.new(KEY, s.encode("utf-8"), hashlib.sha256).hexdigest()


STORE = [
    _line(
        op="add",
        id="aaa111",
        text="office: north wing",
        key="office",
        src={"trust": "user", "path": "api"},
        ts=TS[0],
    ),
    _line(
        op="add",
        id="bbb222",
        text="office: north wing moved east",
        key="office",
        src={"trust": "user", "path": "api", "author": AUTHOR},
        ts=TS[1],
    ),
    _line(
        op="add",
        id="ccc333",
        text="office: north wing annex",
        key=None,
        src={"trust": "agent", "path": "mcp"},
        ts=TS[2],
    ),
    _line(op="key_conflict", id="ccc333", holder="bbb222", reason="trust", ts=TS[3]),
    _line(
        op="add",
        id="ddd444",
        text="neutral note with an address",
        key=None,
        src={"trust": "external", "path": "api", "author": AUTHOR},
        ts=TS[4],
    ),
    _line(op="quarantine", id="ddd444", reason="payment_content", ts=TS[5]),
    _line(
        op="update",
        id="bbb222",
        text="office: north wing, third floor",
        src={"trust": "user", "path": "api"},
        ts=TS[6],
    ),
    _line(op="add", id="eee555", text="neutral tea note", key=None, ts=TS[7]),
    _line(op="supersede", id="eee555", reason="trust_upgrade", ts=TS[8]),
]


def test_a_record_retired_by_a_later_keyed_add_shows_who_when_and_by_what(tmp_path):
    r, rows = _run(_store(tmp_path, STORE), "aaa111")
    assert r.returncode == 0, r.stderr
    assert rows == [
        {
            "seq": 0,
            "event": "add",
            "ts": TS[0],
            "trust": "user",
            "path": "api",
            "author_hmac": None,
        },
        {
            "seq": 1,
            "event": "retired",
            "ts": TS[1],
            "by": "bbb222",
            "how": "key",
            "writer": {"trust": "user", "path": "api", "author_hmac": _hmac(AUTHOR)},
        },
    ], rows


def test_the_retiring_add_names_what_it_retired_and_later_updates_follow(tmp_path):
    r, rows = _run(_store(tmp_path, STORE), "bbb222")
    assert r.returncode == 0, r.stderr
    assert rows == [
        {
            "seq": 1,
            "event": "add",
            "ts": TS[1],
            "trust": "user",
            "path": "api",
            "author_hmac": _hmac(AUTHOR),
            "retires": ["aaa111"],
        },
        {"seq": 3, "event": "key_conflict", "ts": TS[3], "reason": "trust", "by": "ccc333"},
        {
            "seq": 6,
            "event": "update",
            "ts": TS[6],
            "trust": "user",
            "path": "api",
            "author_hmac": None,
        },
    ], rows


def test_a_refused_keyed_add_retires_nothing(tmp_path):
    r, rows = _run(_store(tmp_path, STORE), "ccc333")
    assert rows == [
        {
            "seq": 2,
            "event": "add",
            "ts": TS[2],
            "trust": "agent",
            "path": "mcp",
            "author_hmac": None,
        },
        {"seq": 3, "event": "key_conflict", "ts": TS[3], "reason": "trust", "holder": "bbb222"},
    ], rows


def test_quarantine_explicit_supersede_and_legacy(tmp_path):
    p = _store(tmp_path, STORE)
    assert _run(p, "ddd444")[1] == [
        {
            "seq": 4,
            "event": "add",
            "ts": TS[4],
            "trust": "external",
            "path": "api",
            "author_hmac": _hmac(AUTHOR),
        },
        {"seq": 5, "event": "quarantine", "ts": TS[5], "reason": "payment_content"},
    ]
    assert _run(p, "eee555")[1] == [
        {
            "seq": 7,
            "event": "add",
            "ts": TS[7],
            "trust": "legacy",
            "path": None,
            "author_hmac": None,
        },
        {"seq": 8, "event": "supersede", "ts": TS[8], "reason": "trust_upgrade"},
    ]


def test_a_flag_shows_its_reason_code_and_never_free_text(tmp_path):
    p = _store(
        tmp_path,
        STORE
        + [
            _line(op="flag", a="aaa111", b="bbb222", why="numeric_mismatch", ts=TS[9]),
            json.dumps(
                {
                    "op": "flag",
                    "a": "aaa111",
                    "b": "eee555",
                    "why": "neutral words from before 0.3.1",
                }
            ),
        ],
    )
    rows = _run(p, "aaa111")[1]
    assert rows[-2:] == [
        {"seq": 9, "event": "flag", "ts": TS[9], "why": "numeric_mismatch", "with": "bbb222"},
        {"seq": 10, "event": "flag", "ts": None, "why": None, "with": "eee555"},
    ], rows


def test_no_text_slot_key_or_plain_author_is_printed(tmp_path):
    p = _store(tmp_path, STORE)
    out = "".join(
        _run(p, rid)[0].stdout for rid in ("aaa111", "bbb222", "ccc333", "ddd444", "eee555")
    )
    for piece in ("north wing", "office", "neutral", AUTHOR):
        assert piece not in out, piece


def test_without_a_key_file_the_author_is_null_and_no_key_is_created(tmp_path):
    p = _store(tmp_path, STORE, key=False)
    r, rows = _run(p, "bbb222")
    assert r.returncode == 0 and rows[0]["author_hmac"] is None and "erasure_key" in r.stderr, (
        rows,
        r.stderr,
    )
    assert not (p.parent / ".erasure_key").exists()


def test_it_only_reads_on_a_torn_tail_it_refuses_and_changes_nothing(tmp_path):
    p = _store(tmp_path, STORE)
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"op": "add", "id": "fff666", "te')  # a torn last line, no newline
    before = p.read_bytes()
    r, rows = _run(p, "aaa111")
    assert r.returncode == 1 and rows == [] and "repair --quarantine-bad-lines" in r.stderr, (
        r.stderr
    )
    assert p.read_bytes() == before and not os.path.exists(str(p) + ".torn")


def test_an_unknown_id_exits_1_and_needs_an_id(tmp_path):
    p = _store(tmp_path, STORE)
    r, rows = _run(p, "zzz999")
    assert r.returncode == 1 and rows == [] and "zzz999" in (r.stderr + r.stdout)
    r = subprocess.run(
        [sys.executable, GOVERN, "provenance", str(p)], capture_output=True, text=True, timeout=60
    )
    assert r.returncode != 0 and "--id" in (r.stderr + r.stdout)


def test_the_module_function_matches_the_command(tmp_path):
    spec = importlib.util.spec_from_file_location("amem_governance", GOVERN)
    gov = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gov)
    p = _store(tmp_path, STORE)
    events = [json.loads(x) for x in STORE]
    assert gov.provenance(events, "aaa111", KEY) == _run(p, "aaa111")[1]
