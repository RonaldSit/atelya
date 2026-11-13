"""Op-log schema version and timestamps (W2) in governance and attest.

Spec: web3-features-spec W2 (atelya repo: docs/web3-features-spec.md; the rules and
the inventory: docs/oplog-schema.md). This file is identical in atelya and
atelya-public; atelya also checks its own copy of the parser against TS_VECTORS.

  W2.2  every event governance writes carries ts (RFC 3339 UTC, microseconds, Z) and v: 2
  W2.3  every old time format is read, in memory only; no old line is rewritten
  W2.4  one small parser (no datetime.fromisoformat, which rejects Z on 3.10)
  W2.6  a line with v above 2 (or a v that is not a positive integer) is refused,
        naming the file, the line and the version found, before anything is changed
  W2.7  audit, replay, retention and attest read the new fields

Expected epochs come from calendar.timegm, never from the parser under test.
Neutral marker strings only; temp dirs only.

Run:  pytest tests/test_schema_v2.py -q
"""

import calendar
import importlib.util
import json
import os
import re
import subprocess
import sys
import time

import pytest

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

TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


def _us(y, mo, d, h=0, mi=0, s=0, us=0, off_min=0):
    """Epoch microseconds of a UTC wall time, minus a zone offset in minutes."""
    return (calendar.timegm((y, mo, d, h, mi, s)) - off_min * 60) * 10**6 + us


# (input, epoch microseconds or None for "refused"). Shared with atelya's own parser.
TS_VECTORS = [
    ("2026-11-04T12:34:56.123456Z", _us(2026, 11, 4, 12, 34, 56, 123456)),
    ("2026-11-04T12:34:56Z", _us(2026, 11, 4, 12, 34, 56)),
    ("2026-11-04T12:34:56.1Z", _us(2026, 11, 4, 12, 34, 56, 100000)),
    ("2026-11-04T12:34:56.000001Z", _us(2026, 11, 4, 12, 34, 56, 1)),
    ("2026-11-04T12:34:56.123456789Z", _us(2026, 11, 4, 12, 34, 56, 123456)),
    ("2026-11-04T12:34:56.9999999Z", _us(2026, 11, 4, 12, 34, 56, 999999)),
    ("2026-11-04t12:34:56.5z", _us(2026, 11, 4, 12, 34, 56, 500000)),
    ("2026-11-04T12:34:56.5+05:30", _us(2026, 11, 4, 12, 34, 56, 500000, 330)),
    ("2026-11-04T12:34:56-08:00", _us(2026, 11, 4, 12, 34, 56, 0, -480)),
    ("2026-11-04T12:34:56+00:00", _us(2026, 11, 4, 12, 34, 56)),
    ("2026-11-04T12:34:56-00:00", _us(2026, 11, 4, 12, 34, 56)),
    ("2026-11-04T00:30:00+01:00", _us(2026, 11, 3, 23, 30)),
    ("1970-01-01T00:00:00Z", 0),
    ("2024-02-29T23:59:59.999999Z", _us(2024, 2, 29, 23, 59, 59, 999999)),
    ("2000-01-01T00:00:00Z", _us(2000, 1, 1)),
    ("2026-11-04T12:34:56", None),
    ("2026-11-04 12:34:56Z", None),
    ("2026-11-04T12:34:56.Z", None),
    ("2026-11-04T12:34:56.1234567890Z", None),
    ("2026-02-29T00:00:00Z", None),
    ("2026-13-01T00:00:00Z", None),
    ("2026-00-10T00:00:00Z", None),
    ("2026-11-31T00:00:00Z", None),
    ("2026-11-04T24:00:00Z", None),
    ("2026-11-04T12:60:00Z", None),
    ("2016-12-31T23:59:60Z", None),
    ("2026-11-04T12:34:56+24:00", None),
    ("2026-11-04T12:34:56+05:60", None),
    ("2026-11-04T12:34:56+0530", None),
    ("2026-11-04T12:34:56ZZ", None),
    (" 2026-11-04T12:34:56Z", None),
    ("2026-11-04T12:34:56Z\n", None),
    ("２０２６-11-04T12:34:56Z", None),
    ("2026-11-0٤T12:34:56Z", None),
    ("26-11-04T12:34:56Z", None),
    ("2026-11-4T12:34:56Z", None),
    ("", None),
    (None, None),
    (1793795696.0, None),
    (1793795696, None),
    (True, None),
    (["2026-11-04T12:34:56Z"], None),
    ({"ts": "2026-11-04T12:34:56Z"}, None),
]

# (epoch microseconds, the string format_ts writes)
FORMAT_VECTORS = [
    (_us(2026, 11, 4, 12, 34, 56, 123456), "2026-11-04T12:34:56.123456Z"),
    (_us(2026, 11, 4, 12, 34, 56), "2026-11-04T12:34:56.000000Z"),
    (0, "1970-01-01T00:00:00.000000Z"),
    (_us(2024, 2, 29, 23, 59, 59, 999999), "2024-02-29T23:59:59.999999Z"),
    (_us(2038, 1, 19, 3, 14, 8, 1), "2038-01-19T03:14:08.000001Z"),
]


# (event, the time event_time gives it). Shared with atelya's own copy.
EVENT_TIME_CASES = [
    ({"created_at": 1000.5}, 1000.5),
    ({"created_at": 7}, 7),
    ({"created_at": 1000.5, "ts": "2026-11-04T12:34:56Z"}, 1000.5),
    ({"ts": 2000.25}, 2000.25),
    ({"ts": "1970-01-01T00:16:40.5Z"}, 1000.5),
    ({"created_at": None, "ts": "1970-01-01T00:16:40Z"}, 1000.0),
    ({"created_at": "1970-01-01T00:16:40Z"}, None),
    ({"created_at": True}, None),
    ({"created_at": float("nan")}, None),
    ({"created_at": float("inf")}, None),
    ({"created_at": 10**400}, None),
    ({"ts": "not a time"}, None),
    ({"ts": False}, None),
    ({}, None),
]


def _need(mod, name):
    assert hasattr(mod, name), f"{mod.__name__}.{name} is missing (W2 not implemented)"
    return getattr(mod, name)


def _parsed_us(fn, value):
    got = fn(value)
    return None if got is None else round(got * 10**6)


def write_lines(path, lines, end="\n"):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines) + end)
    return str(path)


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def new_lines(path, before):
    data = read_bytes(path)
    assert data.startswith(before), "an old line was rewritten"
    return [json.loads(x) for x in data[len(before) :].decode("utf-8").splitlines() if x.strip()]


# ================================ W2.4 parser =====================================
@pytest.mark.parametrize("value,want", TS_VECTORS, ids=[repr(v)[:40] for v, _ in TS_VECTORS])
def test_parse_ts_vectors(value, want):
    assert _parsed_us(_need(gov, "parse_ts"), value) == want


@pytest.mark.parametrize("us,want", FORMAT_VECTORS)
def test_format_ts_vectors(us, want):
    assert _need(gov, "format_ts")(us / 10**6) == want


def test_format_then_parse_is_exact_to_the_microsecond():
    fmt, parse = _need(gov, "format_ts"), _need(gov, "parse_ts")
    for us in [0, 1, 999999, 1793795696123456, 1793795696999999, 4102444799999999]:
        s = fmt(us / 10**6)
        assert TS_RE.fullmatch(s), s
        assert _parsed_us(parse, s) == us, s
    now = time.time()
    assert abs(parse(fmt(now)) - now) < 1e-6


@pytest.mark.parametrize("event,want", EVENT_TIME_CASES)
def test_event_time_rules(event, want):
    assert _need(gov, "event_time")(event) == want


# ================================ W2.2 governance writes ===========================
def _v1_log(tmp_path):
    return write_lines(
        tmp_path / "ops.jsonl",
        [
            json.dumps(
                {
                    "op": "add",
                    "id": "a1",
                    "text": "neutral alpha note",
                    "key": None,
                    "created_at": 1000.0,
                }
            ),
            json.dumps(
                {
                    "op": "add",
                    "id": "a2",
                    "text": "neutral beta note",
                    "key": None,
                    "created_at": 2000.0,
                }
            ),
            json.dumps(
                {
                    "op": "add",
                    "id": "a3",
                    "text": "neutral gamma note",
                    "key": None,
                    "created_at": 3000.0,
                }
            ),
        ],
    )


def _assert_v2(ev, t0, t1):
    assert ev.get("v") == 2 and type(ev.get("v")) is int, ev
    assert isinstance(ev.get("ts"), str) and TS_RE.fullmatch(ev["ts"]), ev
    assert "created_at" not in ev, ev
    t = _need(gov, "parse_ts")(ev["ts"])
    assert t0 - 1e-6 <= t <= t1 + 1e-6, (ev["ts"], t0, t1)


@pytest.mark.parametrize("hard", [False, True])
def test_erase_writes_v2_events(tmp_path, hard):
    p = _v1_log(tmp_path)
    before = read_bytes(p)
    t0 = time.time()
    out = gov.erase(p, "beta", hard=hard)
    t1 = time.time()
    assert out["matched"] == 1
    if hard:
        lines = [json.loads(x) for x in read_bytes(p).decode().splitlines()]
        assert [e["id"] for e in lines[:2]] == ["a1", "a3"]
        evs = lines[2:]
        assert [e["op"] for e in evs] == ["purge"]
    else:
        evs = new_lines(p, before)
        assert [e["op"] for e in evs] == ["forget"]
    for ev in evs:
        _assert_v2(ev, t0, t1)


@pytest.mark.parametrize("hard", [False, True])
def test_retention_writes_v2_events(tmp_path, hard):
    p = _v1_log(tmp_path)
    before = read_bytes(p)
    t0 = time.time()
    out = gov.retention(p, max_active=1, hard=hard)
    t1 = time.time()
    assert out["retired"] == 2
    if hard:
        evs = [json.loads(x) for x in read_bytes(p).decode().splitlines()][1:]
        assert [e["op"] for e in evs] == ["purge", "purge"]
    else:
        evs = new_lines(p, before)
        assert [e["op"] for e in evs] == ["forget", "forget"]
    for ev in evs:
        _assert_v2(ev, t0, t1)


# ================================ W2.3 / W2.7 readers ==============================
MIXED = [
    {"text": "neutral legacy line", "id": "L1"},
    {"op": "add", "id": "D1", "text": "neutral dated one", "key": None, "created_at": 1000.0},
    {"op": "add", "id": "N1", "text": "neutral null time", "key": None, "created_at": None},
    {
        "op": "add",
        "id": "S1",
        "text": "neutral string time",
        "key": None,
        "created_at": "2026-11-04T12:34:56Z",
    },
    {"op": "forget", "id": "D1", "ts": 1500.0},
    {"op": "flag", "a": "L1", "b": "N1", "why": "numeric_mismatch"},
    {"op": "update", "id": "N1", "text": "neutral null time revised"},
    {
        "op": "add",
        "id": "V1",
        "text": "neutral v2 add",
        "key": None,
        "created_at": 2000.0,
        "ts": "1970-01-01T00:33:20.000000Z",
        "v": 2,
    },
    {
        "op": "add",
        "id": "V2",
        "text": "neutral v2 ts only",
        "key": None,
        "ts": "1970-01-01T00:50:00.250000Z",
        "v": 2,
    },
    {"op": "supersede", "id": "V1", "ts": "1970-01-01T01:00:00.000000Z", "v": 2},
    {
        "op": "flag",
        "a": "S1",
        "b": "V2",
        "why": "negation_cue",
        "ts": "1970-01-01T01:06:40.000000Z",
        "v": 1,
    },
]


def _mixed(tmp_path):
    return write_lines(tmp_path / "mixed.jsonl", [json.dumps(e) for e in MIXED])


def _local(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t))


def test_replay_reads_every_time_format_in_memory_only(tmp_path):
    p = _mixed(tmp_path)
    before = read_bytes(p)
    rec, order = gov.replay(gov.read_log(p))
    assert order == ["L1", "D1", "N1", "S1", "V1", "V2"]
    assert {r: rec[r]["created_at"] for r in order} == {
        "L1": None,
        "D1": 1000.0,
        "N1": None,
        "S1": None,  # A6: a created_at that is not a number is no time
        "V1": 2000.0,  # created_at wins over ts
        "V2": 3000.25,  # a v2 add with ts only
    }
    assert read_bytes(p) == before


def test_audit_timeline_time_column_reads_ts(tmp_path):
    rows = gov.audit_timeline(gov.read_log(_mixed(tmp_path)))
    assert [r["time"] for r in rows] == [
        "",
        _local(1000.0),
        "",
        "",
        _local(1500.0),  # v1 forget: its epoch-float ts
        "",
        "",
        _local(2000.0),
        _local(3000.25),
        _local(3600.0),
        _local(4000.0),
    ]


def test_retention_by_age_reads_a_v2_ts(tmp_path):
    now = time.time()
    old, new = now - 10 * 86400, now - 3600
    fmt = _need(gov, "format_ts")
    p = write_lines(
        tmp_path / "age.jsonl",
        [
            json.dumps(
                {"op": "add", "id": "o1", "text": "neutral old v1", "key": None, "created_at": old}
            ),
            json.dumps(
                {
                    "op": "add",
                    "id": "o2",
                    "text": "neutral old v2",
                    "key": None,
                    "ts": fmt(old),
                    "v": 2,
                }
            ),
            json.dumps(
                {
                    "op": "add",
                    "id": "n1",
                    "text": "neutral new v2",
                    "key": None,
                    "ts": fmt(new),
                    "v": 2,
                }
            ),
            json.dumps({"op": "add", "id": "u1", "text": "neutral undated", "key": None}),
        ],
    )
    out = gov.retention(p, max_age_days=1)
    assert sorted(out["ids"]) == ["o1", "o2"]


def test_readers_never_rewrite_old_lines(tmp_path):
    p = _mixed(tmp_path)
    before = read_bytes(p)
    gov.summary(gov.read_log(p))
    gov.conflicts(gov.read_log(p))
    gov.audit_timeline(gov.read_log(p))
    out = gov.retention(p, max_active=10)
    assert out["retired"] == 0
    assert read_bytes(p) == before


# ================================ W2.6 newer schema ================================
def _newer(tmp_path, v=3, torn=True):
    lines = [
        json.dumps(
            {
                "op": "add",
                "id": "a1",
                "text": "neutral alpha note",
                "key": None,
                "created_at": 1000.0,
            }
        ),
        json.dumps(
            {
                "op": "add",
                "id": "a2",
                "text": "neutral beta note",
                "key": None,
                "ts": "2026-11-04T12:34:56.000000Z",
                "v": v,
            }
        ),
        json.dumps({"op": "forget", "id": "a1", "ts": "2026-11-04T12:34:57.000000Z", "v": 2}),
    ]
    p = tmp_path / "newer.jsonl"
    with open(p, "wb") as f:
        f.write(("\n".join(lines) + "\n").encode())
        if torn:
            f.write(b'{"op": "add", "id": "a3", "te')
    return str(p)


def _assert_refused(exc, path, lineno, category):
    err = _need(gov, "SchemaVersionError")
    assert isinstance(exc, err) and isinstance(exc, gov.OplogError), type(exc)
    assert (exc.lineno, exc.category) == (lineno, category)
    msg = str(exc)
    assert path in msg and f"line {lineno}" in msg, msg
    assert "repair" not in msg, msg  # repair keeps valid JSON objects: it is no remedy here


@pytest.mark.parametrize(
    "call",
    [
        lambda p: gov.read_events(p),
        lambda p: gov.read_log(p),
        lambda p: gov.erase(p, "alpha"),
        lambda p: gov.erase(p, "alpha", hard=True),
        lambda p: gov.retention(p, max_active=1),
        lambda p: gov.retention(p, max_age_days=0, hard=True),
    ],
    ids=["read_events", "read_log", "erase_soft", "erase_hard", "retention_soft", "retention_hard"],
)
def test_newer_schema_is_refused_before_anything_changes(tmp_path, call):
    p = _newer(tmp_path)
    before = read_bytes(p)
    with pytest.raises(Exception) as ei:
        call(p)
    _assert_refused(ei.value, p, 2, "newer_schema")
    assert "version 3" in str(ei.value), str(ei.value)
    assert read_bytes(p) == before
    assert not os.path.exists(p + ".torn")
    assert not os.path.exists(p + ".epoch")


@pytest.mark.parametrize(
    "v,kind",
    [
        (True, "boolean"),
        ("zq7741-marker", "string"),
        (2.0, "number"),
        (None, "null"),
        (0, "integer below 1"),
        (-1, "integer below 1"),
        (["zq7741-marker"], "array"),
        ({"zq7741": "marker"}, "object"),
    ],
)
def test_a_version_that_is_not_a_positive_integer_is_refused(tmp_path, v, kind):
    p = _newer(tmp_path, v=v, torn=False)
    before = read_bytes(p)
    with pytest.raises(Exception) as ei:
        gov.read_events(p)
    _assert_refused(ei.value, p, 2, "bad_schema")
    assert kind in str(ei.value) and "zq7741" not in str(ei.value), str(ei.value)
    assert read_bytes(p) == before


@pytest.mark.parametrize("v", [1, 2])
def test_versions_one_and_two_are_read(tmp_path, v):
    p = _newer(tmp_path, v=v, torn=False)
    assert [n for n, _e in gov.read_events(p)] == [1, 2, 3]


def test_repair_keeps_a_newer_line(tmp_path):
    p = _newer(tmp_path, torn=False)
    with open(p, "ab") as f:
        f.write(b"not json\n")
    out = gov.repair(p, apply=True)
    assert out["bad_lines"] == [{"line": 4, "category": "invalid_json"}]
    assert b'"v": 3' in read_bytes(p)


def _cli(*argv):
    return subprocess.run(
        [sys.executable, *argv], capture_output=True, text=True, timeout=60, cwd=_ROOT
    )


@pytest.mark.parametrize("cmd", ["audit", "summary", "attest"])
def test_cli_refuses_a_newer_store(tmp_path, cmd):
    p = _newer(tmp_path)
    before = read_bytes(p)
    r = _cli(os.path.join(_ROOT, "amem_governance.py"), cmd, p)
    assert r.returncode != 0
    assert f"{p}: line 2" in r.stderr and "version 3" in r.stderr, r.stderr
    assert read_bytes(p) == before
    assert not os.path.exists(p + ".attest.jsonl")


def test_verify_chain_does_not_apply_the_oplog_version_to_a_chain_file(tmp_path):
    chain = attest.build_chain(gov.read_log(_v1_log(tmp_path)), None)
    p = tmp_path / "chain.jsonl"
    write_lines(p, [json.dumps(dict(e, v=3)) for e in chain])  # an unhashed extra field
    r = _cli(os.path.join(_ROOT, "amem_governance.py"), "verify-chain", str(p))
    assert r.returncode == 0 and "VERIFIED" in r.stdout, r.stdout + r.stderr


# ================================ W2.7 attest ======================================
V1_EVENTS = [
    {"op": "add", "id": "k1", "text": "neutral known answer", "key": "k", "created_at": 1000.0},
    {"op": "forget", "id": "k1", "ts": 1500.0},
    {"op": "flag", "a": "k1", "b": "k2", "why": "numeric_mismatch", "ts": 1600.0},
    {"text": "neutral legacy line"},
]
# Produced by amem_attest.py before W2 (atelya-public e250e1d): rebuilding a chain from
# a v1 op-log must hash exactly as before, or it conflicts with its anchors.
V1_ROOT = "509935b50d2316c89061ec1f08e8f8f83bab567173f288a3a9a8fc4440f5f356"


def test_attest_v1_entries_are_unchanged():
    chain = attest.build_chain(V1_EVENTS, None)
    assert [e["ts"] for e in chain] == ["1970-01-01T00:16:40Z", None, None, None]
    assert attest.root_of(chain) == V1_ROOT


def test_attest_reads_the_ts_of_a_v2_event():
    evs = [
        {
            "op": "add",
            "id": "k1",
            "text": "neutral",
            "key": None,
            "created_at": 1000.0,
            "ts": "1970-01-01T00:16:40.000000Z",
            "v": 2,
        },
        {"op": "forget", "id": "k1", "ts": "1970-01-01T00:25:00.250000Z", "v": 2},
        {"op": "update", "id": "k1", "text": "neutral two", "v": 2},
    ]
    chain = attest.build_chain(evs, None)
    assert [e["ts"] for e in chain] == [
        "1970-01-01T00:16:40.000000Z",
        "1970-01-01T00:25:00.250000Z",
        None,
    ]
    assert attest.verify_chain(chain, None)[0]


@pytest.mark.parametrize("v", [3, True, "2", 0])
def test_attest_refuses_an_event_it_cannot_read(v):
    evs = [
        {"op": "add", "id": "k1", "text": "neutral", "created_at": 1.0},
        {"op": "forget", "id": "k1", "v": v},
    ]
    with pytest.raises(ValueError) as ei:
        attest.build_chain(evs, None)
    assert "seq 1" in str(ei.value) and "version" in str(ei.value), str(ei.value)


def test_attest_cli_refuses_a_newer_oplog(tmp_path):
    p = _newer(tmp_path, torn=False)
    r = _cli(os.path.join(_ROOT, "amem_attest.py"), "attest", p)
    assert r.returncode != 0 and p in r.stderr and "version 3" in r.stderr, r.stderr
    assert not os.path.exists(p + ".attest.jsonl")
