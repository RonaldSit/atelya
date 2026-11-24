"""Audit events for the op-log lines atelya-govern writes (atelya web3-features-spec W4, owner
decision of 2026-11-23): the forget lines of a soft erase or retention, purge markers, release.

One CloudEvents 1.0 object per line, to the file named by AMEM_EMIT_FILE and to the entry
points of atelya.emit_hooks, after the op-log lock is released. amem_governance.audit_event
decides what may leave from EVENT_FIELDS: record ids, reason codes, src.trust and src.path,
HMACs; never text, a slot key, a pattern or a note.

The same file in atelya and atelya-public. Op-logs are written here line by line; no engine
is needed. Run: pytest tests/test_govern_emit.py -q
"""

import hashlib
import hmac
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import amem_governance as G  # noqa: E402

OLD_A, OLD_B = "5f0c2b1e9a3d", "0a1b2c3d4e5f"  # 12 hex digits: ids of atelya 0.3.4 and earlier
NEW = "8129af40e22c4400b3828813ec7a5410"  # a uuid4 in hex
TS = "2026-11-01T00:00:00.000000Z"
USER = {"trust": "user", "path": "api"}
SECRET = "zebra crossing plan"  # the text an erase pattern matches


def add(rid, text, n=1.0, **extra):
    return dict({"op": "add", "id": rid, "text": text, "key": None, "created_at": n}, **extra)


@pytest.fixture
def oplog(tmp_path, monkeypatch):
    monkeypatch.delenv("AMEM_EMIT_FILE", raising=False)
    monkeypatch.setattr(G, "_purge_hooks", lambda: [])
    path = tmp_path / "data" / "user_x.jsonl"
    path.parent.mkdir()
    rows = [
        add(OLD_A, f"neutral note about the {SECRET}", 1.0, src=USER, ts=TS, v=2),
        add(OLD_B, "neutral note about the harbor", 2.0, src=USER, ts=TS, v=2),
        add(NEW, f"neutral second note about the {SECRET}", 3.0, src=USER, ts=TS, v=2),
    ]
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return str(path)


@pytest.fixture
def sink(tmp_path, monkeypatch):
    out = tmp_path / "events.jsonl"
    monkeypatch.setenv("AMEM_EMIT_FILE", str(out))

    def read():
        if not out.exists():
            return []
        return [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]

    read.path = str(out)
    return read


def raw_lines(path):
    with open(path, "rb") as f:
        return [x for x in f.read().split(b"\n") if x.strip()]


def digest_of(path, raw):
    ev = json.loads(raw)
    if ev.get("id") == NEW:
        return {"line_sha256": hashlib.sha256(raw).hexdigest()}
    key = G.erasure_key(os.path.dirname(path))
    return {"line_hmac": hmac.new(key, raw, hashlib.sha256).hexdigest(), "keyed": True}


def envelope_ok(path, event, raw, kind):
    digest = digest_of(path, raw)
    want = {
        "specversion": "1.0",
        "id": digest.get("line_sha256") or digest["line_hmac"],
        "source": "urn:atelya:store:user_x",
        "type": f"io.atelya.memory.{kind}",
        "time": json.loads(raw)["ts"],
        "datacontenttype": "application/json",
    }
    assert {k: event.get(k) for k in want} == want
    assert set(event) == set(want) | {"data"}
    assert {
        k: v for k, v in event["data"].items() if k.startswith("line_") or k == "keyed"
    } == digest


def test_a_soft_erase_emits_one_event_per_forget_line_without_the_pattern(oplog, sink):
    out = G.erase(oplog, SECRET)
    assert out["matched"] == 2 and out["audit_events"] == {"delivered": 2, "failed": 0}
    written = raw_lines(oplog)[3:]
    events = sink()
    assert len(events) == len(written) == 2
    for event, raw in zip(events, written, strict=True):
        line = json.loads(raw)
        assert line["op"] == "forget" and SECRET in line["reason"]
        envelope_ok(oplog, event, raw, "forget")
        assert {k: v for k, v in event["data"].items() if k == "id"} == {"id": line["id"]}
        assert "reason" not in event["data"], "a pattern is not a reason code"
    with open(sink.path, encoding="utf-8") as f:
        assert "zebra" not in f.read()
    assert {e["data"]["id"] for e in events} == {OLD_A, NEW}
    assert ["keyed" in e["data"] for e in sorted(events, key=lambda e: e["data"]["id"] == NEW)] == [
        True,
        False,
    ]


def test_a_soft_retention_emits_its_forget_lines_with_the_reason_code(oplog, sink):
    out = G.retention(oplog, max_active=1)
    assert out["retired"] == 2 and out["audit_events"]["delivered"] == 2
    events = sink()
    for event, raw in zip(events, raw_lines(oplog)[3:], strict=True):
        envelope_ok(oplog, event, raw, "forget")
        assert (
            event["data"]["reason"] == "retention" and event["data"]["id"] == json.loads(raw)["id"]
        )


def test_a_hard_erase_emits_its_purge_markers_and_nothing_of_the_kept_lines(oplog, sink):
    out = G.erase(oplog, SECRET, hard=True)
    assert out["matched"] == 2 and out["audit_events"] == {"delivered": 2, "failed": 0}
    lines = raw_lines(oplog)
    assert [json.loads(x)["op"] for x in lines] == ["add", "purge", "purge"]
    events = sink()
    assert len(events) == 2
    for event, raw in zip(events, lines[1:], strict=True):
        line = json.loads(raw)
        envelope_ok(oplog, event, raw, "purge")
        assert event["data"]["id"] == line["id"] and event["data"]["reason"] == line["reason"]
        assert line["reason"].startswith("erasure:hmac-sha256:") and "note" in line
        assert "note" not in event["data"]
    with open(sink.path, encoding="utf-8") as f:
        text = f.read()
    assert "zebra" not in text and "harbor" not in text and "compliance" not in text


def test_a_hard_retention_emits_its_purge_markers(oplog, sink):
    out = G.retention(oplog, max_active=2, hard=True)
    assert out["retired"] == 1 and out["audit_events"]["delivered"] == 1
    (event,) = sink()
    envelope_ok(oplog, event, raw_lines(oplog)[-1], "purge")
    assert event["data"]["reason"] == "retention" and event["data"]["id"] == OLD_A


def test_a_release_emits_its_line(oplog, sink):
    assert G.release(oplog, OLD_B) == {
        "released": OLD_B,
        "audit_events": {"delivered": 1, "failed": 0},
    }
    (event,) = sink()
    envelope_ok(oplog, event, raw_lines(oplog)[-1], "release")
    assert event["data"]["id"] == OLD_B and event["data"]["reason"] == "operator"
    assert G.release(oplog, "nosuchrecord")["released"] is None and len(sink()) == 1


def test_without_a_sink_nothing_is_built_and_no_key_is_made(oplog):
    out = G.erase(oplog, SECRET)
    assert out == {"matched": 2, "mode": "soft", "ids": sorted([OLD_A, NEW])}
    assert not os.path.exists(os.path.join(os.path.dirname(oplog), ".erasure_key"))
    assert G._EMIT_PENDING == []


def test_a_hook_that_fails_does_not_fail_the_command_or_the_other_sinks(oplog, monkeypatch):
    got = []

    def bad(event):
        raise RuntimeError("neutral hook failure")

    monkeypatch.setattr(G, "_emit_sinks", lambda: ([("bad", bad), ("good", got.append)], 0))
    out = G.erase(oplog, SECRET)
    assert out["matched"] == 2 and out["audit_events"] == {"delivered": 2, "failed": 2}
    assert [e["type"] for e in got] == ["io.atelya.memory.forget"] * 2


def test_a_hook_gets_its_own_copy_of_the_event(oplog, monkeypatch):
    seen = []

    def greedy(event):
        event["data"]["id"] = "changed by the hook"

    monkeypatch.setattr(G, "_emit_sinks", lambda: ([("greedy", greedy), ("next", seen.append)], 0))
    G.release(oplog, OLD_B)
    assert seen[0]["data"]["id"] == OLD_B


def test_events_are_delivered_after_the_lock_is_released(oplog, monkeypatch):
    depths = []

    def watch(event):
        held = G._HELD.get(os.path.abspath(oplog))
        depths.append(held[1] if held else 0)

    monkeypatch.setattr(G, "_emit_sinks", lambda: ([("watch", watch)], 0))
    G.erase(oplog, SECRET)
    G.retention(oplog, max_active=1, hard=True)
    G.release(oplog, OLD_B)
    assert len(depths) >= 3 and set(depths) == {0}


def test_events_of_written_lines_leave_even_when_the_command_fails_later(oplog, monkeypatch):
    got = []
    monkeypatch.setattr(G, "_emit_sinks", lambda: ([("good", got.append)], 0))

    def broken(path):
        raise OSError("neutral failure after the write")

    monkeypatch.setattr(G, "_bump_epoch", broken)
    with pytest.raises(OSError):
        G.erase(oplog, SECRET)
    assert len(got) == 2 and G._EMIT_PENDING == []


def test_a_repair_emits_nothing(oplog, sink):
    with open(oplog, "ab") as f:
        f.write(b"this line is not json\n")
    assert G.repair(oplog, apply=True)
    assert sink() == []


STRAY = {
    "text": "neutral stray text",
    "key": "neutral-slot",
    "note": "neutral note",
    "created_at": 9,
}


@pytest.mark.parametrize("op", sorted(G.EVENT_FIELDS))
def test_only_what_the_registry_lists_for_the_type_can_leave(op):
    fields = G.EVENT_FIELDS[op]["fields"]
    line = {"op": op, "id": OLD_A, "a": OLD_A, "b": OLD_B, "holder": OLD_B, "ts": TS, "v": 2}
    line.update(reason="neutral_code", why="neutral_code", src=dict(USER, author="neutral author"))
    line.update(STRAY)
    raw = json.dumps(line).encode()
    data = G.audit_event("/x/user_x.jsonl", raw, line, b"k" * 32)["data"]
    allowed = {"line_hmac", "keyed"} | (
        {"id", "a", "b", "holder", "reason", "why", "src"} & set(fields)
    )
    assert set(data) == allowed, (op, sorted(data))
    assert not {"text", "key", "note", "created_at"} & set(data)
    if "src" in data:
        assert set(data["src"]) == {"trust", "path", "author_hmac"}
    assert "neutral stray" not in json.dumps(data) and "neutral author" not in json.dumps(data)


def test_a_type_the_registry_does_not_know_carries_only_the_digest():
    line = {"op": "invented", "id": OLD_A, "reason": "neutral_code", "text": "neutral", "ts": TS}
    raw = json.dumps(line).encode()
    event = G.audit_event("/x/user_x.jsonl", raw, line, b"k" * 32)
    assert event["type"] == "io.atelya.memory.invented" and set(event["data"]) == {
        "line_hmac",
        "keyed",
    }
    odd = dict(line, op="Not A Type")
    assert G.audit_event("/x/u.jsonl", raw, odd, b"k" * 32)["type"] == "io.atelya.memory.unknown"


def test_a_free_text_reason_or_id_never_leaves():
    line = {
        "op": "forget",
        "id": "an id with spaces",
        "reason": "erasure:/neutral pattern/",
        "ts": TS,
    }
    raw = json.dumps(line).encode()
    data = G.audit_event("/x/user_x.jsonl", raw, line, b"k" * 32)["data"]
    assert set(data) == {"line_hmac", "keyed"}


def test_the_key_is_needed_only_for_a_keyed_line_or_an_author():
    assert G.audit_needs_key({"op": "forget", "id": OLD_A})
    assert not G.audit_needs_key({"op": "forget", "id": NEW})
    assert G.audit_needs_key({"op": "add", "id": NEW, "src": dict(USER, author="neutral author")})
    line = {"op": "forget", "id": NEW, "reason": "retention", "ts": TS}
    raw = json.dumps(line).encode()
    event = G.audit_event("/x/user_x.jsonl", raw, line, None)
    assert event["id"] == hashlib.sha256(raw).hexdigest() and "keyed" not in event["data"]
