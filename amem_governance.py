#!/usr/bin/env python3
"""amem_governance.py — enterprise governance over amem's append-only op-log.

The market's #1 unmet need for agent memory (multiple 2026 surveys): "Can memories be audited?
How are conflicting memories resolved? What's the retention/deletion policy?" amem already
event-sources every operation into an append-only JSONL op-log; this module turns that into the
governance FEATURES enterprises require — without touching the core.

Op-log events (amem memory.py): {"op":"add","id","text","key","created_at"} | {"op":"update",...}
| {"op":"supersede","id"} | {"op":"forget","id"} | {"op":"key_conflict","id","holder","key","reason"}
| {"op":"flag","a","b","why":<reason code>}. Only add and update carry record text; every other
event names records only through id, a, b and holder (REF_FIELDS), and carries reason codes or
HMACs. Older logs may hold key_conflict events with a "text" excerpt and no id, and flags whose
"why" is text; a hard purge removes them with their record.
Schema version and time (atelya docs/oplog-schema.md): every event written since schema 2
carries "ts" (RFC 3339 UTC with microseconds and Z) and "v": 2. ts is authoritative; an add
written by atelya also keeps "created_at" (epoch seconds, deprecated, the same instant as its
ts), so older readers still date it. A line without "v" is version 1. Readers take ts first;
old time formats (created_at or ts as epoch seconds) are read in memory only, never rewritten.
A line with "v" above 2, or a "v" that is not a positive integer, is refused before anything
is changed, naming the file, the line and the version found.
Superseded/forgotten records are RETAINED (status change, not removal) => full auditable history.

Features (all pure-python over the op-log; no amem / GPU / API):
  audit      — chronological timeline of every memory operation (exportable JSON/CSV)
  lineage    — one memory's full provenance: born -> updated -> superseded/forgotten, by what
  conflicts  — contradiction flags + supersede decisions: which memory won, and why
  erase      — GDPR right-to-erasure: --soft (auditable forget, text retained) vs --hard
               (true content removal by rewriting the log; the purge itself is logged)
  retention  — auto-forget/purge by age or active-count window

KEY TENSION it resolves: an append-only log is perfect for AUDIT but conflicts with ERASURE
(forget leaves the text in the log). Governance needs BOTH — soft-forget for audit, hard-purge
for compliance, with the purge action itself recorded. Naive stores get this wrong.

CLI:
  python amem_governance.py audit   <oplog.jsonl> [--out audit.json|audit.csv]
  python amem_governance.py lineage <oplog.jsonl> --id <rid>
  python amem_governance.py conflicts <oplog.jsonl>
  python amem_governance.py erase   <oplog.jsonl> --match <regex> [--hard [--drop-attest]]
  python amem_governance.py retention <oplog.jsonl> --max-age-days N [--hard [--drop-attest]]
  python amem_governance.py attest    <oplog.jsonl> [--out chain.jsonl] [--key K|--keyfile F]
  python amem_governance.py attest    <oplog.jsonl> --v2 [--out chain.jsonl]
  python amem_governance.py verify-chain <chain.jsonl> [--key K|--keyfile F]
  python amem_governance.py verify-chain <chain.jsonl> [--oplog <oplog.jsonl>]
  python amem_governance.py list-quarantine <oplog.jsonl>
  python amem_governance.py release <oplog.jsonl> --id <rid>
  python amem_governance.py export-digest <chain.jsonl> [--out digest.txt]
  python amem_governance.py anchor-ots <chain.jsonl> [--calendar URL] [--allow-network]
  python amem_governance.py anchor-ots --digest-file <digest.txt> [--calendar URL] [--allow-network]
  python amem_governance.py upgrade-ots <proof.ots> [--calendar URL] [--allow-network]
  python amem_governance.py verify-ots <proof.ots> <chain.jsonl> [--bitcoin-node URL]
  python amem_governance.py verify-ots <proof.ots> --digest-file <digest.txt> [--bitcoin-node URL]
  python amem_governance.py repair --quarantine-bad-lines <oplog.jsonl> [--apply]
  python amem_governance.py --selftest

Hard purge (erase --hard, retention --hard): removes the record's lines, every event naming
it, matching lines of <oplog>.torn and <oplog>.corrupt, and its .vec lines; the purge marker
holds HMAC-SHA256 of the erase pattern with <data dir>/.erasure_key (created on first need,
mode 0600, not enforced on Windows, where the file relies on the ACL of the data directory's
location; never deleted by erase or retention; back it up with the data directory, or
existing HMACs can no longer be checked; markers written before hold a plain SHA-256 and are
left as they are). With a v1 chain at <oplog>.attest.jsonl it refuses, because that chain
stores every event verbatim; --drop-attest deletes the chain file first. With a v2 chain
there (attest --v2: hashes only) it first verifies the chain against the op-log (refusing
on any mismatch), then appends one redaction record per purged record naming the seqs of
the attested lines it removed. Chains written elsewhere with --out are not checked.

Attest v2 (attest --v2; atelya docs/attest-v2.md): one entry per op-log line holding only a
digest of the line's exact bytes: a plain SHA-256 when the line names its record by a uuid4
(122 random bits), else HMAC-SHA256 with <data dir>/.erasure_key (every id atelya writes
today has 48 bits, so verifying those entries needs that key). Re-running attest --v2
verifies the chain, then appends entries for the new lines. verify-chain recomputes every
line from the op-log (--oplog, or the chain path without .attest.jsonl) and names the first
problem: a modified, reordered, inserted or missing line, a redaction naming a line that
still exists, a broken link or a missing key. Lines after the chain are reported as not yet
attested.

Quarantine (atelya docs/trust-recall.md): atelya hides a record below user trust whose text
holds a wallet address, and writes {"op":"quarantine","id","reason":"payment_content"} for it.
list-quarantine prints the ids still quarantined (ids only, never text). release writes
{"op":"release","id","reason":"operator"}: the record is re-certified as user and appears in
recall again. That is the operator's decision; nothing releases a record on its own.

OpenTimestamps (atelya docs/ots.md; needs atelya-attest[ots], Python 3.11 or later): explicit
commands only, nothing runs on its own. export-digest writes the v2 chain head (32 bytes, hex)
and its last seq, so anchoring can happen on another machine. anchor-ots sends only that
32-byte digest to OpenTimestamps calendars (default: the client's aggregators, or
ATELYA_OTS_CALENDARS, or --calendar) and writes <chain>.ots plus <chain>.ots.note.json; it
prints the last seq it covers: lines attested after it are not covered until the next anchor.
upgrade-ots asks the calendars named in the proof (only whitelisted ones) for the Bitcoin
attestation. verify-ots checks the proof against the chain (the head of the chain as it was
at that seq) or a digest file, then against your own bitcoind over RPC (--bitcoin-node, or
its bitcoin.conf); exit 0 verified, 3 pending (no Bitcoin attestation yet), 1 failed. With
AMEM_PRIVATE=1, anchor-ots and upgrade-ots refuse unless --allow-network is given.
Post-purge hooks: after every HARD erase/retention, each installed entry point
in the group "atelya.purge_hooks" is called with the op-log path, the purged
record ids with SHA-256 digests of their texts, and (erase only) the matcher.
Hooks never receive the erased text. The CLI prints every hook and its
outcome, or, when none is installed, the files the purge cleaned ("cleaned"
in the JSON line); a failed hook exits 1.

Exit codes (erase, retention): 0 on success, including when nothing matched
or nothing was due. 1 means a post-purge hook failed, or the command refused
or could not run: the default attest chain exists (hard purge), a bad op-log
line, an invalid --match regex, a missing op-log; the message says which.
Argument errors (an unknown option, a missing value) exit 2. Erasure is
idempotent: re-running after a failed hook is expected to match nothing; a
refused command refuses again until its cause is fixed. To know whether
anything was erased, read "matched" (erase) or "retired" (retention) from
the JSON line the command prints first, not the exit code.

Integrity (attest — hash-chain the op-log): SHA-256 (or HMAC-SHA256 with a key) chain per
the 2026 audit-trail pattern (arXiv 2601.20727; NIST SP 800-92). Tamper-EVIDENT, not
tamper-PROOF: any modification/deletion/reorder is detected and located; anchor the printed
root externally (WORM/notary) for full assurance.
"""

import argparse
import contextlib
import csv
import datetime
import errno
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import shlex
import sys
import threading
import time
import signal

log = logging.getLogger("amem_governance")


# ---- op-log parsing and locking -------------------------------------------------
# Same rules as amem/oplog.py, kept as a separate copy because this module is
# stdlib-only and standalone. The parse vectors in the atelya repo check both.
# - A torn tail (last line without a newline that is not a JSON object) is
#   appended unchanged to <file>.torn and truncated, under the lock.
# - Any other bad line raises OplogError: never skipped silently.
# - Every append, torn-tail move, rewrite and repair holds <oplog>.lock.
LOCK_SUFFIX = ".lock"
TORN_SUFFIX = ".torn"
CORRUPT_SUFFIX = ".corrupt"
_DESCR = {
    "invalid_json": "is not valid JSON",
    "not_object": "is JSON but not an object",
    "torn_tail": "is an incomplete last line, and the directory is read-only so it cannot be moved",
}
_READONLY_ERRNOS = {errno.EACCES, errno.EPERM, errno.EROFS}


class OplogError(ValueError):
    """A bad line the reader will not skip. Never carries the line's content."""

    def __init__(self, path, lineno, category):
        self.path, self.lineno, self.category = path, lineno, category
        q = shlex.quote(path)
        super().__init__(
            f"{path}: line {lineno} {_DESCR.get(category, category)}; refusing to load it. "
            f"List bad lines: atelya-govern repair --quarantine-bad-lines {q} "
            f"(then add --apply to move them to {path}.corrupt)"
        )


# ---- schema version and times (same rules as amem/oplog.py; atelya checks both) ----
SCHEMA_VERSION = 2  # what new events carry; the highest version this code reads


class SchemaVersionError(OplogError):
    """A line this code cannot read: written by a newer version ("newer_schema"),
    or with a "v" that is not a positive integer ("bad_schema"). found is the
    version (newer_schema) or the JSON type (bad_schema), never a value from the
    line. repair is no remedy (it keeps every JSON object), so it is not named."""

    def __init__(self, path, lineno, category, found):
        self.path, self.lineno, self.category, self.found = path, lineno, category, found
        if category == "newer_schema":
            msg = (
                f"{path}: line {lineno} has schema version {found}; this version of atelya "
                f"reads versions up to {SCHEMA_VERSION}, so the op-log was written by a newer "
                f"version. Refusing to load it; upgrade atelya to read it."
            )
        else:
            msg = (
                f"{path}: line {lineno} has a schema version that is not a positive integer "
                f"(a JSON {found}); refusing to load it."
            )
        ValueError.__init__(self, msg)


def _json_type(x):
    if x is None:
        return "null"
    if isinstance(x, bool):
        return "boolean"
    if isinstance(x, int):
        return "integer below 1"
    if isinstance(x, float):
        return "number"
    if isinstance(x, str):
        return "string"
    return "array" if isinstance(x, list) else "object"


def check_schema(path, lineno, ev):
    """Raise SchemaVersionError unless this code reads ev's version (absent = 1)."""
    if "v" not in ev:
        return
    v = ev["v"]
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise SchemaVersionError(path, lineno, "bad_schema", _json_type(v))
    if v > SCHEMA_VERSION:
        raise SchemaVersionError(path, lineno, "newer_schema", v)


_TS_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?([Zz]|[+-][0-9]{2}:[0-9]{2})"
)


def format_ts(t):
    """The ts of a new event: RFC 3339, UTC, microseconds, trailing Z."""
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def parse_ts(s):
    """Epoch seconds of an RFC 3339 string, or None. A fraction beyond microseconds
    is cut, not rounded; a missing zone, a leap second or an impossible date is None.
    A regex plus datetime: the same on Python 3.10, whose fromisoformat rejects Z."""
    if not isinstance(s, str):
        return None
    m = _TS_RE.fullmatch(s)
    if m is None:
        return None
    y, mo, d, h, mi, sec, frac, zone = m.groups()
    off = 0
    if zone not in ("Z", "z"):
        oh, om = int(zone[1:3]), int(zone[4:6])
        if oh > 23 or om > 59:
            return None
        off = (oh * 60 + om) * (-1 if zone[0] == "-" else 1)
    try:
        dt = datetime.datetime(
            int(y),
            int(mo),
            int(d),
            int(h),
            int(mi),
            int(sec),
            int((frac or "").ljust(6, "0")[:6]),
            tzinfo=datetime.timezone(datetime.timedelta(minutes=off)),
        )
    except ValueError:
        return None
    return dt.timestamp()


def _finite(x):
    """x if it is a finite number (not a bool), else None."""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return None
    try:
        return x if math.isfinite(x) else None
    except OverflowError:  # an int too large for a float
        return None


def event_time(ev):
    """The time of an event in epoch seconds, or None, from every format written so
    far. ts is authoritative: an RFC 3339 ts (v2), else an epoch-number ts (v1), else
    created_at (a number; deprecated, still written on add by atelya for older
    readers, always equal to its ts). A created_at that is not a number is no time
    (an old-format line: sorts as 0)."""
    t = parse_ts(ev.get("ts"))
    if t is None:
        t = _finite(ev.get("ts"))
    if t is None:
        t = _finite(ev.get("created_at"))
    return t


def _stamp(ev, now=None):
    """A new event as written since schema 2: its ts and v."""
    return dict(ev, ts=format_ts(time.time() if now is None else now), v=SCHEMA_VERSION)


def classify(raw):
    """(category, event) for one line without its newline. category is None
    for a JSON object, else "blank", "invalid_json" or "not_object"."""
    s = raw.strip()
    if not s:
        return "blank", None
    try:
        ev = json.loads(s.decode("utf-8"))
    except ValueError:  # includes JSONDecodeError and UnicodeDecodeError
        return "invalid_json", None
    if not isinstance(ev, dict):
        return "not_object", None
    return None, ev


if os.name == "nt":  # NOT checked: no Windows test machine
    import msvcrt

    def _lock_fd(fd):
        # LK_LOCK retries only once a second; poll the non-blocking form instead
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return
            except OSError as e:
                if e.errno not in (errno.EACCES, errno.EDEADLOCK):
                    raise
                time.sleep(0.005)

    def _unlock_fd(fd):
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock_fd(fd):
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock_fd(fd):
        fcntl.flock(fd, fcntl.LOCK_UN)


_HELD = {}  # abspath -> [RLock, depth, fd]; reentrant within a process
_HELD_GUARD = threading.Lock()


@contextlib.contextmanager
def oplog_lock(path, readonly_ok=False):
    """Hold <path>.lock (exclusive, across processes and threads; reentrant in
    one thread). Yields True. With readonly_ok, a directory where the lock file
    cannot be created yields False instead of raising: the caller may only read."""
    key = os.path.abspath(path)
    with _HELD_GUARD:
        ent = _HELD.setdefault(key, [threading.RLock(), 0, None])
    with ent[0]:
        if ent[1] == 0:
            try:
                fd = os.open(key + LOCK_SUFFIX, os.O_RDWR | os.O_CREAT, 0o600)
            except OSError as e:
                if readonly_ok and e.errno in _READONLY_ERRNOS:
                    yield False
                    return
                raise
            try:
                _lock_fd(fd)
            except BaseException:
                os.close(fd)
                raise
            ent[2] = fd
        ent[1] += 1
        try:
            yield True
        finally:
            ent[1] -= 1
            if ent[1] == 0:
                fd, ent[2] = ent[2], None
                try:
                    _unlock_fd(fd)
                finally:
                    os.close(fd)


def _fix_tail(path, f, keep_torn=True, terminate_valid=False):
    """Caller holds the lock; f is `path` opened for reading and writing.
    A last line without a newline that is a JSON object gets its newline
    (terminate_valid); anything else is a torn tail: appended unchanged to
    <path>.torn (keep_torn) and truncated. Returns the torn bytes or None."""
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size == 0:
        return None
    f.seek(size - 1)
    if f.read(1) == b"\n":
        return None
    f.seek(0)
    data = f.read()
    start = data.rfind(b"\n") + 1
    tail = data[start:]
    if classify(tail)[0] is None:
        if terminate_valid:
            f.seek(0, os.SEEK_END)
            f.write(b"\n")
        return None
    if keep_torn:
        with open(path + TORN_SUFFIX, "ab") as t:
            t.write(tail + b"\n")
    f.truncate(start)
    log.warning(
        "%s: torn last line (%d bytes) %s",
        path,
        len(tail),
        f"moved to {path + TORN_SUFFIX}" if keep_torn else "dropped",
    )
    return tail


def _append_lines(path, lines):
    """Append lines (str, no newline) under the lock, after a clean tail."""
    with oplog_lock(path):
        with open(path, "ab+") as f:
            _fix_tail(path, f, keep_torn=True, terminate_valid=True)
            for line in lines:
                f.write((line + "\n").encode("utf-8"))


def _load_lines(path, repair=True, schema=True):
    """[(lineno, raw bytes, event or None for a blank line)] for every line, read
    under the lock. repair: move a torn tail to <path>.torn first; without it (or
    in a read-only directory) a torn tail raises like any other bad line.
    schema: refuse a line this code cannot read (check_schema) before anything is
    changed, ahead of any other bad line (op-logs; not a chain file)."""
    if not os.path.exists(path):
        raise FileNotFoundError(errno.ENOENT, "op-log not found", path)
    with oplog_lock(path, readonly_ok=True) as locked:
        with open(path, "rb") as f:
            data = f.read()
        pieces = data.split(b"\n")
        terminated = data.endswith(b"\n") or not data
        if terminated:
            pieces = pieces[:-1]
        parsed = [classify(raw) for raw in pieces]
        if schema:
            for i, (cat, ev) in enumerate(parsed, 1):
                if cat is None:
                    check_schema(path, i, ev)
        if repair and not terminated and parsed[-1][0] is not None:
            if not locked:
                raise OplogError(path, len(pieces), "torn_tail")
            with open(path, "rb+") as f:
                _fix_tail(path, f, keep_torn=True)
            pieces, parsed, terminated = pieces[:-1], parsed[:-1], True
    out = []
    for i, (cat, ev) in enumerate(parsed, 1):
        if cat == "blank":
            out.append((i, pieces[i - 1], None))
            continue
        if cat is not None:
            if i == len(pieces) and not terminated:
                cat = "torn_tail"
            raise OplogError(path, i, cat)
        out.append((i, pieces[i - 1], ev))
    return out


def _rewrite(path, raw_lines, extra_events):
    """Caller holds the lock. Atomically replace the op-log with raw_lines
    (bytes, unchanged, in order) followed by extra_events."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        for raw in raw_lines:
            f.write(raw + b"\n")
        for ev in extra_events:
            f.write((json.dumps(ev, ensure_ascii=False) + "\n").encode("utf-8"))
    os.replace(tmp, path)


def _promote(ev):
    if "op" not in ev and "text" in ev:  # legacy {"text":...} == add
        return {
            "op": "add",
            "text": ev["text"],
            "id": ev.get("id"),
            "key": ev.get("key"),
            "created_at": ev.get("created_at"),
        }
    return ev


def read_events(path, repair=True, schema=True):
    """[(lineno, event)] for every non-blank line, as written (no legacy promotion)."""
    return [(n, ev) for n, _raw, ev in _load_lines(path, repair, schema) if ev is not None]


def read_log(path, repair=True, schema=True):
    return [_promote(ev) for _n, ev in read_events(path, repair, schema)]


def replay(events):
    """Reconstruct current records {id:{text,key,created_at,status,history:[ops]}} from the log."""
    rec = {}
    order = []
    for ev in events:
        op = ev.get("op", "add")
        rid = ev.get("id")
        if op == "add":
            if rid and ev.get("key") is not None:
                for record in rec.values():  # same-key supersede (the lifecycle)
                    if record["status"] == "active" and record.get("key") == ev.get("key"):
                        record["status"] = "superseded"
                        record["history"].append("superseded-by-" + str(rid))
            if rid is None:
                rid = f"_auto{len(order)}"
            rec[rid] = {
                "id": rid,
                "text": ev.get("text", ""),
                "key": ev.get("key"),
                "created_at": event_time(ev),  # ts first, else created_at; None: no time
                "status": "active",
                "actor": ev.get("actor") or ev.get("source"),
                "history": ["add"],
            }
            order.append(rid)
        elif op == "update" and rid in rec:
            rec[rid]["text"] = ev.get("text", rec[rid]["text"])
            rec[rid]["history"].append("update")
        elif op == "supersede" and rid in rec:
            rec[rid]["status"] = "superseded"
            rec[rid]["history"].append("supersede")
        elif op == "forget" and rid in rec:
            rec[rid]["status"] = "deleted"
            rec[rid]["history"].append("forget")
        elif op == "purge" and rid in rec:
            rec[rid]["status"] = "purged"
            rec[rid]["text"] = "<redacted>"
            rec[rid]["history"].append("purge")
    return rec, order


def audit_timeline(events):
    rows = []
    for i, ev in enumerate(events):
        op = ev.get("op", "add")
        ts = event_time(ev)  # ts in either format, else created_at
        when = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)) if ts else ""
        if op == "flag":
            detail = f"contradiction a={ev.get('a')} b={ev.get('b')} why={ev.get('why')}"
            rid = ev.get("a")
        else:
            rid = ev.get("id")
            txt = (ev.get("text") or "")[:80]
            detail = txt + (f"  [key={ev.get('key')}]" if ev.get("key") else "")
        rows.append(
            {
                "seq": i,
                "time": when,
                "op": op,
                "id": rid or "",
                "actor": ev.get("actor") or ev.get("source") or "",
                "detail": detail,
            }
        )
    return rows


def export(rows, out):
    fmt = "csv" if out.lower().endswith(".csv") else "json"
    if fmt == "csv":
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["seq", "time", "op", "id", "actor", "detail"])
            w.writeheader()
            w.writerows(rows)
    else:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=1, ensure_ascii=False)
    return out, fmt


def lineage(events, rid):
    evs = []
    for i, ev in enumerate(events):
        if ev.get("id") == rid or ev.get("a") == rid or ev.get("b") == rid:
            evs.append((i, ev.get("op", "add"), ev))
    return evs


def conflicts(events):
    rec, _ = replay(events)
    out = []
    for ev in events:
        if ev.get("op") == "flag":
            a, b = ev.get("a"), ev.get("b")
            # winner = whichever side is still active (the lifecycle prefers newer/active)
            wa = rec.get(a, {}).get("status")
            wb = rec.get(b, {}).get("status")
            winner = (
                a
                if wa == "active" and wb != "active"
                else (b if wb == "active" and wa != "active" else "unresolved")
            )
            out.append(
                {
                    "a": a,
                    "b": b,
                    "why": ev.get("why"),
                    "a_status": wa,
                    "b_status": wb,
                    "winner": winner,
                }
            )
    return out


def _match_ids(events, pattern):
    regex = re.compile(pattern, re.I)
    rec, _ = replay(events)
    return [rid for rid, record in rec.items() if regex.search(record.get("text") or "")]


def _purge_vec(oplog_path, ids, keep_ids=None):
    """F3a: drop erased records from the `<oplog>.vec` sidecar.

    The sidecar caches one embedding per record. A hard erasure that rewrites the
    op-log but leaves the sidecar behind is NOT a complete erasure: embeddings are
    approximately invertible back to text. With keep_ids (the record ids the
    rewritten op-log still has), every other line goes too: an old-format line
    without an id gets a new random id at every load, so its embeddings pile up
    under ids no op-log line names. The sidecar is a cache; whatever is dropped is
    recomputed on the next load. Returns the number of lines removed.
    """
    vec_path = oplog_path + ".vec"
    if not os.path.exists(vec_path) or not ids:
        return 0
    targets = set(ids)
    kept, dropped = [], 0
    with open(vec_path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                vid = json.loads(s).get("id")
                if vid in targets or (keep_ids is not None and vid not in keep_ids):
                    dropped += 1
                    continue
            except Exception:
                pass  # unparseable line: keep it, never lose data silently
            kept.append(s)
    if not dropped:
        return 0
    tmp = vec_path + ".purge.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            for s in kept:
                f.write(s + "\n")
        os.replace(tmp, vec_path)  # atomic
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return dropped


# ---- what a hard purge removes (events carry no record content) ------------------
ATTEST_SUFFIX = ".attest.jsonl"
ERASURE_KEY_NAME = ".erasure_key"
# The fields through which an event names a record. Every event type, old or new,
# names records only through these; a hard purge removes every event naming a
# purged id in any of them.
REF_FIELDS = ("id", "a", "b", "holder")
_TEXT_FIELD = re.compile(r'"text"\s*:\s*"')
_WINDOW = 20


class AttestPresent(ValueError):
    """A hard purge would leave the purged text in the default attest chain file."""


class ChainMismatch(ValueError):
    """An attest v2 chain does not match its op-log (or cannot be checked): attest --v2
    will not extend it and a hard purge will not redact over it."""


def _attest_module():
    try:
        import amem_attest
    except ImportError:  # loaded from another directory: use the copy next to this file
        import importlib.util

        here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "amem_attest.py")
        spec = importlib.util.spec_from_file_location("amem_attest", here)
        amem_attest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(amem_attest)
    return amem_attest


def _existing_key(data_dir):
    """The data directory's .erasure_key, or None when there is none. Never creates it."""
    path = os.path.join(data_dir, ERASURE_KEY_NAME)
    try:
        with open(path, "rb") as f:
            key = f.read()
    except FileNotFoundError:
        return None
    if len(key) != 32:
        raise RuntimeError(f"{path}: not a 32-byte key; refusing to compute HMACs with it")
    return key


def _is_v2_chain_file(chain_path):
    """True when the chain file's first entry is an attest v2 entry."""
    with open(chain_path, "rb") as f:
        for raw in f:
            if raw.strip():
                cat, ev = classify(raw.rstrip(b"\n"))
                return cat is None and ev.get("v") == 2 and not isinstance(ev.get("v"), bool)
    return False


def _read_chain(chain_path):
    return [ev for _n, ev in read_events(chain_path, repair=False, schema=False)]


def _verify_lines_v2(chain, lines, key):
    """verify_chain_v2 over _load_lines output; the error also names the file line."""
    pairs = [(raw, ev) for _n, raw, ev in lines if ev is not None]
    linenos = [n for n, _raw, ev in lines if ev is not None]
    report = _attest_module().verify_chain_v2(chain, pairs, key)
    err = report["error"]
    if err and err.get("line") is not None:
        err["lineno"] = linenos[err["line"]]
    return report, pairs


def _chain_problem(chain_path, oplog_path, report):
    e = report["error"]
    where = f" at seq={e['seq']}" if e.get("seq") is not None else ""
    where += f", {oplog_path} line {e['lineno']}" if e.get("lineno") is not None else ""
    return f"{chain_path} does not match {oplog_path}: {e['kind']}{where}" + (
        f" ({e['detail']})" if e.get("detail") else ""
    )


def attest_v2(path, out=None):
    """Create or extend the attest v2 chain of an op-log (default <oplog>.attest.jsonl).
    An existing chain must be v2 and must match the op-log; then entries for the lines
    after it are appended. Holds <path>.lock. Returns chain, appended, last_seq, head."""
    att = _attest_module()
    chain_path = out or path + ATTEST_SUFFIX
    data_dir = os.path.dirname(os.path.abspath(path))
    with oplog_lock(path):
        lines = _load_lines(path)
        chain = _read_chain(chain_path) if os.path.exists(chain_path) else []
        if chain and not att.is_v2(chain):
            raise ChainMismatch(
                f"{chain_path} is a v1 chain (it stores every event verbatim); attest --v2 does "
                "not extend it. Move it out of the way, or choose another --out, to start a v2 chain."
            )
        if chain:
            key = _existing_key(data_dir)
            report, pairs = _verify_lines_v2(chain, lines, key)
            if not report["ok"]:
                raise ChainMismatch(_chain_problem(chain_path, path, report))
            start = len(pairs) - report["unattested"]
        else:
            key = erasure_key(data_dir)
            pairs, start = [(raw, ev) for _n, raw, ev in lines if ev is not None], 0
        new = att.extend_chain_v2(chain, pairs[start:], key)[len(chain) :]
        with open(chain_path, "a", encoding="utf-8") as f:
            for e in new:
                f.write(json.dumps(e) + "\n")
            f.flush()
            os.fsync(f.fileno())
    full = chain + new
    last = next((e["seq"] for e in reversed(full) if "seq" in e), None)
    return {
        "chain": chain_path,
        "appended": len(new),
        "last_seq": last,
        "head": att.chain_head_v2(full),
    }


def verify_v2(chain_path, oplog_path):
    """The verify_chain_v2 report of a v2 chain against its op-log (read only: the key is
    read, never created, and a torn tail is not moved)."""
    chain = _read_chain(chain_path)
    report, _pairs = _verify_lines_v2(
        chain,
        _load_lines(oplog_path, repair=False),
        _existing_key(os.path.dirname(os.path.abspath(oplog_path))),
    )
    return report


def erasure_key(data_dir):
    """The data directory's key for HMACs written to disk: 32 random bytes in
    <data_dir>/.erasure_key, created here on first need (O_CREAT|O_EXCL, mode 0600).
    It never leaves the machine and is never exported; erase and retention never
    delete it. Back it up with the data directory: without it, existing HMACs can
    no longer be checked. amem.serve_common.erasure_key reads and writes the same file."""
    path = os.path.join(data_dir, ERASURE_KEY_NAME)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        pass
    else:
        try:
            key = secrets.token_bytes(32)
            while key:
                key = key[os.write(fd, key) :]
            os.fsync(fd)
        finally:
            os.close(fd)
    for _ in range(200):  # another process may still be writing it
        with open(path, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key
        time.sleep(0.01)
    raise RuntimeError(f"{path}: not a 32-byte key; refusing to compute HMACs with it")


def _hmac_hex(oplog_path, value):
    key = erasure_key(os.path.dirname(os.path.abspath(oplog_path)))
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


# ---- OpenTimestamps anchoring of the v2 head (atelya web3-features-spec W5) --------------
OTS_EXTRA = (
    "the OpenTimestamps commands need the extra atelya-attest[ots] (Python 3.11 or later): "
    "pip install 'atelya-attest[ots]'"
)
OTS_CALENDARS_ENV = "ATELYA_OTS_CALENDARS"
_TRUTHY = ("1", "true", "yes", "on")


class OtsUnavailable(RuntimeError):
    """The [ots] extra (opentimestamps, opentimestamps-client) is not installed."""


class OtsError(ValueError):
    """An OpenTimestamps command could not do its job; the message says why."""


def _ots():
    """The OpenTimestamps classes, or OtsUnavailable naming the extra."""
    try:
        import opentimestamps.calendar as calendar
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import (
            StreamDeserializationContext,
            StreamSerializationContext,
        )
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    except ImportError as e:
        raise OtsUnavailable(OTS_EXTRA) from e
    return argparse.Namespace(
        calendar=calendar,
        Bitcoin=BitcoinBlockHeaderAttestation,
        Pending=PendingAttestation,
        OpSHA256=OpSHA256,
        In=StreamDeserializationContext,
        Out=StreamSerializationContext,
        Detached=DetachedTimestampFile,
        Timestamp=Timestamp,
    )


def _private_network_refusal(cmd, allow_network):
    if allow_network:
        return
    if (os.environ.get("AMEM_PRIVATE", "") or "").strip().lower() in _TRUTHY:
        raise OtsError(
            f"{cmd} sends a digest to OpenTimestamps calendars over the network, and private mode "
            "(AMEM_PRIVATE) refuses that. Anchor from another machine instead: run "
            "`atelya-govern export-digest <chain>` here, copy the digest file, and run "
            "`atelya-govern anchor-ots --digest-file <file>` there. Or pass --allow-network."
        )


def _v2_head(chain_path):
    """(head bytes, last seq, the chain) of an attest v2 chain file."""
    att = _attest_module()
    chain = _read_chain(chain_path)
    if not att.is_v2(chain):
        raise ChainMismatch(
            f"{chain_path} is not an attest v2 chain: OpenTimestamps anchors the head of a v2 chain "
            "(attest --v2)"
        )
    last = next((e["seq"] for e in reversed(chain) if "seq" in e), None)
    return bytes.fromhex(att.chain_head_v2(chain)), last, chain


def export_digest(chain_path, out=None):
    """Write the v2 chain head as hex, then `# last_seq N`, to out (default
    <chain>.digest). Needs no network and no extra."""
    head, last, _chain = _v2_head(chain_path)
    out = out or chain_path + ".digest"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"{head.hex()}\n# last_seq {last}\n")
    return {"digest_file": out, "head": head.hex(), "last_seq": last}


def _read_digest_file(path):
    with open(path, encoding="utf-8") as f:
        lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
    try:
        digest = bytes.fromhex(lines[0])
    except (IndexError, ValueError):
        digest = b""
    if len(digest) != 32:
        raise OtsError(
            f"{path}: the first line must be a 32-byte digest in hex (export-digest writes it)"
        )
    last = None
    for ln in lines[1:]:
        if ln.startswith("# last_seq "):
            tail = ln[len("# last_seq ") :]
            last = int(tail) if tail.isdigit() else None
    return digest, last


def _calendars(calendars, o):
    if calendars:
        return list(calendars)
    env = (os.environ.get(OTS_CALENDARS_ENV) or "").split()
    return env or list(o.calendar.DEFAULT_AGGREGATORS)


def _scope(last):
    if last is None:
        return "the last seq this digest covers is not known (the digest file does not say)"
    return (
        f"covers the attest v2 chain up to seq {last}; lines attested after seq {last} are not "
        "covered until the next anchor"
    )


def anchor_ots(
    chain_path=None, digest_file=None, out=None, calendars=None, timeout=10, allow_network=False
):
    """Send only the 32-byte chain head to OpenTimestamps calendars and write the proof
    (<chain or digest file>.ots) and its note (<proof>.note.json)."""
    _private_network_refusal("anchor-ots", allow_network)
    o = _ots()
    if digest_file:
        digest, last = _read_digest_file(digest_file)
        base = digest_file
    else:
        digest, last, _chain = _v2_head(chain_path)
        base = chain_path
    ts = o.Timestamp(digest)
    accepted, errors = [], []
    for url in _calendars(calendars, o):
        try:
            ts.merge(
                o.calendar.RemoteCalendar(url, user_agent="atelya-govern").submit(
                    digest, timeout=timeout
                )
            )
            accepted.append(url)
        except Exception as e:  # each calendar on its own; the result says which failed
            errors.append(f"{url}: {type(e).__name__}: {e}"[:300])
    if not accepted:
        raise OtsError("no calendar accepted the digest: " + "; ".join(errors))
    proof = out or base + ".ots"
    tmp = proof + ".tmp"
    with open(tmp, "wb") as f:
        o.Detached(o.OpSHA256(), ts).serialize(o.Out(f))
    os.replace(tmp, proof)
    note = {
        "proof": os.path.basename(proof),
        "head": digest.hex(),
        "last_seq": last,
        "anchored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "calendars": accepted,
        "scope": _scope(last),
    }
    with open(proof + ".note.json", "w", encoding="utf-8") as f:
        json.dump(note, f, indent=1)
        f.write("\n")
    return {
        "proof": proof,
        "head": digest.hex(),
        "last_seq": last,
        "calendars": accepted,
        "errors": errors,
        "scope": note["scope"],
    }


def _load_proof(o, proof):
    with open(proof, "rb") as f:
        try:
            return o.Detached.deserialize(o.In(f))
        except Exception as e:
            raise OtsError(
                f"{proof}: not a readable OpenTimestamps proof ({type(e).__name__}: {e})"
            ) from e


def _bitcoin_heights(o, dtf):
    return sorted(
        {a.height for _m, a in dtf.timestamp.all_attestations() if isinstance(a, o.Bitcoin)}
    )


def upgrade_ots(proof, calendars=None, timeout=10, allow_network=False):
    """Ask the calendars named in the proof for its Bitcoin attestation. Only calendars on
    the client's whitelist, or given with --calendar / ATELYA_OTS_CALENDARS, are asked."""
    _private_network_refusal("upgrade-ots", allow_network)
    o = _ots()
    dtf = _load_proof(o, proof)
    allowed = (
        set(_calendars(calendars, o)) if calendars or os.environ.get(OTS_CALENDARS_ENV) else set()
    )
    before = _bitcoin_heights(o, dtf)
    asked, skipped, pending = [], [], []

    def walk(stamp):
        yield stamp
        for sub in stamp.ops.values():
            yield from walk(sub)

    for stamp in list(walk(dtf.timestamp)):
        for att in list(stamp.attestations):
            if not isinstance(att, o.Pending):
                continue
            if att.uri not in allowed and att.uri not in o.calendar.DEFAULT_CALENDAR_WHITELIST:
                skipped.append(att.uri)
                continue
            asked.append(att.uri)
            try:
                upgraded = o.calendar.RemoteCalendar(
                    att.uri, user_agent="atelya-govern"
                ).get_timestamp(stamp.msg, timeout=timeout)
            except o.calendar.CommitmentNotFoundError:
                pending.append(att.uri)
                continue
            except Exception as e:
                pending.append(f"{att.uri} ({type(e).__name__})")
                continue
            stamp.merge(upgraded)
    after = _bitcoin_heights(o, dtf)
    changed = after != before
    if changed:
        tmp = proof + ".tmp"
        with open(tmp, "wb") as f:
            dtf.serialize(o.Out(f))
        os.replace(tmp, proof)
    return {
        "proof": proof,
        "changed": changed,
        "bitcoin_heights": after,
        "asked": asked,
        "skipped": skipped,
        "pending": pending,
    }


def verify_ots(proof, chain_path=None, digest_file=None, bitcoin_node=None, btc_network="mainnet"):
    """Check a proof against the chain (or a digest file), then its Bitcoin attestations
    against your own bitcoind. status: verified, pending (no Bitcoin attestation yet) or
    failed (OtsError)."""
    o = _ots()
    dtf = _load_proof(o, proof)
    digest = dtf.file_digest
    covered = chain_last = None
    if digest_file:
        want, covered = _read_digest_file(digest_file)
        if want != digest:
            raise OtsError(f"{proof} does not commit to the digest in {digest_file}")
    else:
        att = _attest_module()
        chain = _read_chain(chain_path)
        if not att.is_v2(chain):
            raise ChainMismatch(f"{chain_path} is not an attest v2 chain")
        k = next((i for i, e in enumerate(chain) if att.entry_hash(e) == digest.hex()), None)
        if k is None:
            raise OtsError(
                f"{proof} does not commit to {chain_path} (no entry of it hashes to the proof's digest)"
            )
        covered = next((e["seq"] for e in reversed(chain[: k + 1]) if "seq" in e), None)
        chain_last = next((e["seq"] for e in reversed(chain) if "seq" in e), None)
    result = {
        "proof": proof,
        "digest": digest.hex(),
        "covered_last_seq": covered,
        "chain_last_seq": chain_last,
    }
    attestations = sorted(
        ((m, a) for m, a in dtf.timestamp.all_attestations() if isinstance(a, o.Bitcoin)),
        key=lambda x: x[1].height,
    )
    if not attestations:
        return dict(result, status="pending")
    import bitcoin
    import bitcoin.rpc

    bitcoin.SelectParams(btc_network)
    proxy = bitcoin.rpc.Proxy(service_url=bitcoin_node) if bitcoin_node else bitcoin.rpc.Proxy()
    problems = []
    for msg, a in attestations:
        try:
            header = proxy.getblockheader(proxy.getblockhash(a.height))
            when = a.verify_against_blockheader(msg, header)
        except Exception as e:  # each attestation on its own; one good one is enough
            problems.append(f"block {a.height}: {type(e).__name__}: {e}"[:300])
            continue
        return dict(result, status="verified", height=a.height, block_time=when)
    raise OtsError("no Bitcoin attestation verified: " + "; ".join(problems))


# ---- payment-content quarantine (atelya web3-features-spec W7) ---------------------------
def list_quarantine(path):
    """{"quarantined": [ids]}: records with a quarantine event and no release after it,
    that the op-log still holds. Ids only."""
    events = [ev for _n, ev in read_events(path)]
    rec, _order = replay([_promote(ev) for ev in events])
    held = []
    for ev in events:
        rid = ev.get("id")
        if not isinstance(rid, str):
            continue
        if ev.get("op") == "quarantine" and rid not in held:
            held.append(rid)
        elif ev.get("op") == "release" and rid in held:
            held.remove(rid)
    return {"quarantined": [r for r in held if r in rec and rec[r]["status"] != "purged"]}


def release(path, rid):
    """Re-certify a record as user (the operator's decision): append a content-free
    release event and bump the purge epoch so running doors reload."""
    with oplog_lock(path):
        events = [ev for _n, _raw, ev in _load_lines(path) if ev is not None]
        rec, _order = replay([_promote(ev) for ev in events])
        if rid not in rec or rec[rid]["status"] == "purged":
            return {"released": None, "reason": f"no record {rid!r} in {path}"}
        _append_lines(
            path, [json.dumps(_stamp({"op": "release", "id": rid, "reason": "operator"}))]
        )
        _bump_epoch(path)
    return {"released": rid}


def _attest_guard(path, drop_attest):
    """Refuse a hard purge while the default v1 attest chain exists: it stores every
    event verbatim, so the purged text would stay in it. drop_attest deletes it.
    Returns True when it was deleted, "v2" for a v2 chain (hashes only: the purge
    appends redaction records instead), else False. Chain files written elsewhere
    (--out) are not checked."""
    chain = path + ATTEST_SUFFIX
    if not os.path.exists(chain):
        return False
    if _is_v2_chain_file(chain):
        return "v2"
    if not drop_attest:
        raise AttestPresent(
            f"{chain} exists: an attest chain stores every op-log event verbatim, including "
            "the text a hard purge removes, so the purge would leave that text there. "
            "Re-run with --drop-attest to delete the chain file and purge (its root no longer "
            "matches afterwards), or move the chain out of the data directory first. Chain "
            "files written elsewhere with --out are not checked."
        )
    os.remove(chain)
    return True


def _record_ids(lines):
    """For each line, the id of the record its add creates, by replay's rule (the
    line's id, else _auto<n> for the n-th add), or None."""
    out, n = [], 0
    for _n, _raw, ev in lines:
        rid = None
        if ev is not None:
            pev = _promote(ev)
            if pev.get("op", "add") == "add":
                rid = pev.get("id")
                if rid is None:
                    rid = f"_auto{n}"
                n += 1
        out.append(rid)
    return out


def _purge_plan(lines, targets):
    """(kept raw lines, {id: [texts]}, ids kept, {line index: [targets]}) for a hard
    purge of `targets`. Dropped: the add line of each target (an id-less old-format
    line by its replay id), every event naming a target in REF_FIELDS, and every old
    key_conflict (no id, written before ids were added to it) whose text excerpt is a
    prefix of a purged text, with no minimum length. Every other line is kept
    unchanged. The last item names, for each dropped line, the targets it belongs to."""
    rids = _record_ids(lines)
    texts = {rid: [] for rid in targets}
    for i, (_n, _raw, ev) in enumerate(lines):
        if ev is None:
            continue
        rid = rids[i] if rids[i] in targets else ev.get("id")
        t = ev.get("text")
        if (
            rid in texts
            and isinstance(t, str)
            and _promote(ev).get("op", "add") in ("add", "update")
        ):
            if t not in texts[rid]:
                texts[rid].append(t)
    kept, kept_ids, removed = [], set(), {}
    for i, (_n, raw, ev) in enumerate(lines):
        if ev is not None:
            why = {rids[i]} if rids[i] in targets else set()
            why.update(
                ev.get(f) for f in REF_FIELDS if isinstance(ev.get(f), str) and ev.get(f) in targets
            )
            ex = ev.get("text")  # only old key_conflict events carry one
            if ev.get("op") == "key_conflict" and isinstance(ex, str) and ex:
                why.update(
                    rid for rid, ts in texts.items() if any(t and t.startswith(ex) for t in ts)
                )
            if why:
                removed[i] = sorted(why, key=str)
                continue
            if rids[i] is not None:
                kept_ids.add(rids[i])
        kept.append(raw)
    return kept, texts, kept_ids, removed


def _v2_precheck(path, lines, guard):
    """Before a hard purge with a v2 chain: the chain must match the op-log. Returns
    (chain, {line index: seq}) or None without a v2 chain."""
    if guard != "v2":
        return None
    chain_path = path + ATTEST_SUFFIX
    chain = _read_chain(chain_path)
    report, _pairs = _verify_lines_v2(
        chain, lines, _existing_key(os.path.dirname(os.path.abspath(path)))
    )
    if not report["ok"]:
        raise ChainMismatch(
            _chain_problem(chain_path, path, report) + "; refusing to purge (nothing was changed)"
        )
    seq_at, k = {}, 0
    for i, (_n, _raw, ev) in enumerate(lines):
        if ev is not None:
            seq_at[i] = report["seq_of_line"][k]
            k += 1
    return chain, seq_at


def _v2_redact(path, v2, removed, targets):
    """After a hard purge with a v2 chain: one redaction record per purged record that
    had attested lines removed, appended to the chain. Returns the redacted seqs."""
    if v2 is None:
        return None
    att = _attest_module()
    chain, seq_at = v2
    new, everything = [], set()
    for rid in sorted(targets, key=str):
        seqs = {seq_at[i] for i, why in removed.items() if rid in why and seq_at[i] is not None}
        if seqs:
            rec = att.redaction_v2(chain + new, seqs, _marker_id(rid))
            new.append(rec)
            everything |= seqs
    if new:
        with open(path + ATTEST_SUFFIX, "a", encoding="utf-8") as f:
            for e in new:
                f.write(json.dumps(e) + "\n")
            f.flush()
            os.fsync(f.fileno())
    return sorted(everything)


def text_forms(text):
    """The forms a text takes on disk: raw, and JSON-escaped with ensure_ascii True
    and False (quotes removed). They cover escaped non-ASCII text, quotes,
    backslashes and newlines."""
    out = [text, json.dumps(text)[1:-1], json.dumps(text, ensure_ascii=False)[1:-1]]
    return [f for i, f in enumerate(out) if f and f not in out[:i]]


def _string_head(s):
    """The JSON string body at the start of s, up to an unescaped quote or the end
    (a torn line may cut it short)."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            out.append(s[i : i + 2])
            i += 2
            continue
        if c == '"':
            break
        out.append(c)
        i += 1
    return "".join(out)


def _holds_purged(line, forms, windows):
    m = _TEXT_FIELD.search(line)
    if m:
        head = _string_head(line[m.end() :])
        if head and any(f.startswith(head) for f in forms):
            return True
    return any(w in line for w in windows)


def _scrub_side_files(path, texts):
    """Drop from <oplog>.torn and <oplog>.corrupt every line holding a purged text: a line with a "text" field whose
    string, maybe truncated, is a prefix of a purged text (no minimum length), and
    any line holding a 20-character substring of one. Texts are matched in all
    text_forms. Returns {side file path: lines dropped} for the files that lost a
    line, in suffix order. Caller holds the lock."""
    forms = [f for t in texts for f in text_forms(t)]
    if not forms:
        return {}
    windows = {f[i : i + _WINDOW] for f in forms for i in range(len(f) - _WINDOW + 1)}
    cleaned = {}
    for suffix in (TORN_SUFFIX, CORRUPT_SUFFIX):
        side = path + suffix
        if not os.path.exists(side):
            continue
        with open(side, "rb") as f:
            data = f.read()
        pieces = data.split(b"\n")
        if data.endswith(b"\n") or not data:
            pieces = pieces[:-1]
        kept = []
        for raw in pieces:
            # "text" and the windows are searched anywhere in the line, so the
            # "<line number><TAB>" prefix of a .corrupt line needs no stripping
            line = raw.decode("utf-8", "replace")
            if not _holds_purged(line, forms, windows):
                kept.append(raw)
        if len(kept) == len(pieces):
            continue
        cleaned[side] = len(pieces) - len(kept)
        if not kept:
            os.remove(side)
            continue
        tmp = side + ".tmp"
        with open(tmp, "wb") as f:
            for raw in kept:
                f.write(raw + b"\n")
        os.replace(tmp, side)
    return cleaned


def _cleaned_names(path, purged, n_vec, side, attest_dropped):
    """Base names of the files a hard purge rewrote or deleted, in a fixed order:
    the op-log (when records were purged), .vec, .torn, .corrupt, the attest chain."""
    names = [os.path.basename(path)] if purged else []
    if n_vec:
        names.append(os.path.basename(path) + ".vec")
    names += [os.path.basename(s) for s in side]
    if attest_dropped:
        names.append(os.path.basename(path) + ATTEST_SUFFIX)
    return names


def _marker_id(rid):
    """The id a purge marker records. An old-format line without an id only has a
    positional replay id (_auto<n>); once its line is gone the next id-less line
    takes that number, so a marker naming it would redact the wrong record on
    replay. Such a marker names no id."""
    return None if isinstance(rid, str) and re.fullmatch(r"_auto\d+", rid) else rid


def _digests(texts):
    return [hashlib.sha256(t.encode("utf-8")).hexdigest() for t in texts]


# F3c: signal running servers. Suffix must match amem/serve_common.PURGE_EPOCH_SUFFIX.
PURGE_EPOCH_SUFFIX = ".epoch"


def _bump_epoch(oplog_path):
    """A running server caches this store in RAM; touching the epoch file makes
    it rebuild on the next request instead of serving erased data.

    Deliberately a separate file from the op-log: the server appends to the log
    constantly, so watching the log's own mtime would reload on every request.
    """
    import os as _os
    import time as _time

    try:
        p = oplog_path + PURGE_EPOCH_SUFFIX
        with open(p, "w", encoding="utf-8") as f:
            f.write(str(_time.time()))
        _os.utime(p, None)
    except OSError:
        pass


PURGE_HOOK_GROUP = "atelya.purge_hooks"


def _purge_hooks():
    """Post-purge hooks installed in this environment: [(name, fn_or_error)].

    A hook is a Python entry point in the group "atelya.purge_hooks", called
    after a HARD purge as fn(oplog_path, purged, match):
      purged  {record_id: [sha256 hex of every text that record ever had]}
      match   callable(str) -> bool, the erase regex (re.I); None for retention
    It never receives the erased text. A product that keeps copies of memory
    text outside the op-log (session caches, tool files) registers one to
    remove them. A hook that fails to load is reported as a failed hook.
    """
    try:
        from importlib.metadata import entry_points

        eps = list(entry_points(group=PURGE_HOOK_GROUP))
    except Exception as e:
        return [("(hook discovery)", e)]
    out = []
    for ep in sorted(eps, key=lambda e: e.name):
        try:
            out.append((ep.name, ep.load()))
        except Exception as e:
            out.append((ep.name, e))
    return out


def run_purge_hooks(oplog_path, purged, match=None):
    """Call every installed post-purge hook. Never raises; returns
    [{"hook": name, "ok": bool, "result" or "error": ...}]."""
    results = []
    for name, fn in _purge_hooks():
        if isinstance(fn, Exception):
            results.append({"hook": name, "ok": False, "error": f"{type(fn).__name__}: {fn}"[:300]})
            continue
        try:
            results.append({"hook": name, "ok": True, "result": fn(oplog_path, purged, match)})
        except Exception as e:
            results.append({"hook": name, "ok": False, "error": f"{type(e).__name__}: {e}"[:300]})
    return results


def erase(path, pattern, hard=False, drop_attest=False):
    """GDPR right-to-erasure. soft: append forget events (auditable, text retained).
    hard: rewrite the log dropping the matched records' content entirely (see
    _purge_plan; also .torn, .corrupt and .vec); log a purge marker holding
    HMAC-SHA256 of the pattern with <data dir>/.erasure_key; then run the post-purge
    hooks (also when nothing matched, so a re-run finishes a cleanup a failed hook
    left undone). A hard erase refuses while <oplog>.attest.jsonl exists, unless
    drop_attest. The read and the write hold <path>.lock; a hard purge keeps every
    other line byte for byte; hooks run after the lock is released."""
    regex = re.compile(pattern, re.I)
    redacted = None
    with oplog_lock(path):
        guard = _attest_guard(path, drop_attest) if hard else False
        attest_dropped = guard is True
        lines = _load_lines(path)
        events = [_promote(ev) for _n, _raw, ev in lines if ev is not None]
        targets = set(_match_ids(events, pattern))
        if not targets and not hard:
            return {"matched": 0, "mode": "soft", "ids": []}
        if not hard:
            _append_lines(
                path,
                [
                    json.dumps(
                        _stamp({"op": "forget", "id": rid, "reason": f"erasure:/{pattern}/"})
                    )
                    for rid in targets
                ],
            )
            _bump_epoch(path)  # F3c
            return {"matched": len(targets), "mode": "soft", "ids": sorted(targets)}
        n_vec, side, digests = 0, {}, {}
        if targets:
            v2 = _v2_precheck(path, lines, guard)
            kept, texts, kept_ids, removed = _purge_plan(lines, targets)
            mark = "erasure:hmac-sha256:" + _hmac_hex(path, pattern)
            markers = [
                _stamp(
                    {
                        "op": "purge",
                        "id": _marker_id(rid),
                        "reason": mark,
                        "note": "content removed for compliance",
                    }
                )
                for rid in sorted(targets)
            ]
            _rewrite(path, kept, markers)
            redacted = _v2_redact(path, v2, removed, targets)
            _bump_epoch(path)  # F3c
            n_vec = _purge_vec(path, targets, keep_ids=kept_ids)  # F3a: the embeddings too
            side = _scrub_side_files(path, [t for ts in texts.values() for t in ts])
            digests = {rid: _digests(ts) for rid, ts in texts.items()}
    hooks = run_purge_hooks(path, digests, lambda text: bool(regex.search(text or "")))
    if not targets:
        out = {"matched": 0, "mode": "hard", "ids": [], "hooks": hooks}
    else:
        out = {
            "matched": len(targets),
            "mode": "hard",
            "ids": sorted(targets),
            "vec_purged": n_vec,
            "side_lines_purged": sum(side.values()),
            "hooks": hooks,
        }
    if redacted is not None:
        out["attest_redacted"] = redacted
    if attest_dropped:
        out["attest_dropped"] = True
    cleaned = _cleaned_names(path, bool(targets), n_vec, side, attest_dropped)
    if cleaned:
        out["cleaned"] = cleaned
    return out


def retention(path, max_age_days=None, max_active=None, hard=False, drop_attest=False):
    """Retire by age and/or active-count window. A hard purge follows the same rules
    as a hard erase (_purge_plan, side files, attest guard). The read and the write
    hold <path>.lock; a hard purge keeps every other line byte for byte; hooks run
    after the lock is released."""
    redacted = None
    with oplog_lock(path):
        guard = _attest_guard(path, drop_attest) if hard else False
        attest_dropped = guard is True
        lines = _load_lines(path)
        events = [_promote(ev) for _n, _raw, ev in lines if ev is not None]
        rec, order = replay(events)
        now = time.time()
        doomed = []
        if max_age_days is not None:
            cut = now - max_age_days * 86400
            doomed += [
                rid
                for rid, record in rec.items()
                if record["status"] == "active" and (record.get("created_at") or now) < cut
            ]
        if max_active is not None:
            active = [rid for rid in order if rec[rid]["status"] == "active"]
            if len(active) > max_active:
                doomed += active[: len(active) - max_active]  # oldest first
        doomed = sorted(set(doomed))
        digests, n_vec, side = {}, 0, {}
        if not doomed:
            if not hard:
                return {"retired": 0, "mode": "soft"}
        elif hard:
            gone = set(doomed)
            v2 = _v2_precheck(path, lines, guard)
            kept, texts, kept_ids, removed = _purge_plan(lines, gone)
            markers = [
                _stamp({"op": "purge", "id": _marker_id(rid), "reason": "retention"}, now)
                for rid in doomed
            ]
            _rewrite(path, kept, markers)
            redacted = _v2_redact(path, v2, removed, gone)
            _bump_epoch(path)  # F3c
            n_vec = _purge_vec(path, gone, keep_ids=kept_ids)  # F3a: the embeddings too
            side = _scrub_side_files(path, [t for ts in texts.values() for t in ts])
            digests = {rid: _digests(ts) for rid, ts in texts.items()}
        else:
            _append_lines(
                path,
                [
                    json.dumps(_stamp({"op": "forget", "id": rid, "reason": "retention"}, now))
                    for rid in doomed
                ],
            )
            _bump_epoch(path)  # F3c
            return {"retired": len(doomed), "mode": "soft", "ids": doomed}
    hooks = run_purge_hooks(path, digests, None)
    out = {"retired": 0, "mode": "hard", "hooks": hooks}
    if doomed:
        out = {"retired": len(doomed), "mode": "hard", "ids": doomed, "hooks": hooks}
    if redacted is not None:
        out["attest_redacted"] = redacted
    if attest_dropped:
        out["attest_dropped"] = True
    cleaned = _cleaned_names(path, bool(doomed), n_vec, side, attest_dropped)
    if cleaned:
        out["cleaned"] = cleaned
    return out


def repair(path, apply=False):
    """Quarantine bad lines. Dry run by default: report each bad line by number
    and category, never its content. apply: under <path>.lock, move each bad
    line unchanged to <path>.corrupt as "<line number><TAB><line>", move a torn
    tail to <path>.torn, and keep every other line byte for byte, in order."""
    with oplog_lock(path):
        with open(path, "rb") as f:
            data = f.read()
        pieces = data.split(b"\n")
        terminated = data.endswith(b"\n") or not data
        if terminated:
            pieces = pieces[:-1]
        bad = []
        for i, raw in enumerate(pieces, 1):
            cat, _ev = classify(raw)
            if i == len(pieces) and not terminated and cat is not None:
                bad.append((i, "torn_tail"))
            elif cat in ("invalid_json", "not_object"):
                bad.append((i, cat))
        result = {
            "oplog": path,
            "bad_lines": [{"line": i, "category": c} for i, c in bad],
            "applied": False,
        }
        if apply and bad:
            corrupt = [(i, pieces[i - 1]) for i, c in bad if c != "torn_tail"]
            torn = [pieces[i - 1] for i, c in bad if c == "torn_tail"]
            if corrupt:
                with open(path + CORRUPT_SUFFIX, "ab") as f:
                    for i, raw in corrupt:
                        f.write(str(i).encode("ascii") + b"\t" + raw + b"\n")
            if torn:
                with open(path + TORN_SUFFIX, "ab") as f:
                    for raw in torn:
                        f.write(raw + b"\n")
            gone = {i for i, _c in bad}
            _rewrite(path, [raw for i, raw in enumerate(pieces, 1) if i not in gone], [])
            _bump_epoch(path)  # F3c: running servers reload
            result["applied"] = True
    return result


def summary(events):
    rec, _ = replay(events)
    status = {}
    for record in rec.values():
        status[record["status"]] = status.get(record["status"], 0) + 1
    nflag = sum(1 for ev in events if ev.get("op") == "flag")
    return {
        "events": len(events),
        "memories": len(rec),
        "by_status": status,
        "contradiction_flags": nflag,
        "auditable": "every add/update/supersede/forget is logged with a timestamp",
        "actor_tracking": "present"
        if any(ev.get("actor") or ev.get("source") for ev in events)
        else "per-user store isolates writers; stamp 'actor' at write-time for per-identity audit",
    }


# ---------------- CLI ----------------
def _print_rows(rows, n=40):
    print(f"{'seq':>4} {'time':<19} {'op':<11} {'id':<10} {'detail'}")
    for record in rows[:n]:
        print(
            f"{record['seq']:>4} {record['time']:<19} {record['op']:<11} {str(record['id'])[:10]:<10} {record['detail'][:70]}"
        )
    if len(rows) > n:
        print(f"... (+{len(rows) - n} more; use --out to export full)")


def _print_hooks(record, hard):
    """Say which post-purge hooks ran and how each ended. Returns the exit code."""
    if not hard:
        print("  post-purge hooks: not run (soft mode keeps the text in the op-log by design)")
        return 0
    hooks = record.get("hooks") or []
    if not hooks:
        purged = record.get("matched", record.get("retired", 0))
        cleaned = ", ".join(record.get("cleaned") or [])
        if purged:
            what = f"cleaned only {cleaned}"
        else:
            what = "nothing was purged" + (f" (deleted {cleaned})" if cleaned else "")
        print(
            f"  post-purge hooks: none installed (entry-point group {PURGE_HOOK_GROUP!r}); {what}"
        )
        return 0
    failed = 0
    for h in hooks:
        if h["ok"]:
            print(
                f"  post-purge hook {h['hook']}: ok {json.dumps(h.get('result'), ensure_ascii=False, default=str)}"
            )
        else:
            failed += 1
            print(f"  post-purge hook {h['hook']}: FAILED {h['error']}")
    if failed:
        print(
            f"  ERASE INCOMPLETE: {failed} post-purge hook(s) failed. Fix the cause and re-run "
            "the same command; it is safe to repeat."
        )
        return 1
    return 0


def main(argv=None):
    if hasattr(signal, "SIGPIPE"):  # standard CLI: exit quietly (141) when piped to head/less
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "cmd",
        nargs="?",
        choices=[
            "audit",
            "lineage",
            "conflicts",
            "erase",
            "retention",
            "summary",
            "attest",
            "verify-chain",
            "repair",
            "export-digest",
            "anchor-ots",
            "upgrade-ots",
            "verify-ots",
            "list-quarantine",
            "release",
        ],
    )
    parser.add_argument("oplog", nargs="?")
    parser.add_argument("target", nargs="?")
    parser.add_argument("--id")
    parser.add_argument("--match")
    parser.add_argument("--out")
    parser.add_argument("--hard", action="store_true")
    parser.add_argument("--max-age-days", type=float)
    parser.add_argument("--max-active", type=int)
    parser.add_argument("--key")
    parser.add_argument("--keyfile")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--quarantine-bad-lines", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--drop-attest", action="store_true")
    parser.add_argument("--v2", action="store_true")
    parser.add_argument("--oplog", dest="chain_oplog")
    parser.add_argument("--digest-file")
    parser.add_argument("--calendar", action="append")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--bitcoin-node")
    parser.add_argument(
        "--btc-network", choices=["mainnet", "testnet", "regtest"], default="mainnet"
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    # parse_intermixed_args, not parse_args: on Python 3.10, 3.11, 3.12.0-3.12.6 and
    # 3.13.0, parse_args gives the optional "oplog" positional zero strings when an
    # option follows the subcommand, then rejects the path as unrecognized, so
    # `repair --quarantine-bad-lines <oplog>` failed there. This parser has no
    # subparsers, no REMAINDER and no mutually exclusive groups, which
    # parse_intermixed_args does not support.
    args = parser.parse_intermixed_args(argv)

    if args.selftest:
        return _selftest()
    if args.target is not None and args.cmd != "verify-ots":
        parser.error(f"unexpected argument {args.target!r} (only verify-ots takes a second path)")
    if args.cmd in ("export-digest", "anchor-ots", "upgrade-ots", "verify-ots"):
        return _ots_main(args)
    if not args.cmd or not args.oplog:
        sys.exit(
            "usage: amem_governance.py {audit|lineage|conflicts|erase|retention|summary|repair} <oplog.jsonl> [...]"
        )
    if not os.path.exists(args.oplog):
        sys.exit(f"op-log not found: {args.oplog}")
    if args.cmd == "repair":
        if not args.quarantine_bad_lines:
            sys.exit("repair needs --quarantine-bad-lines (the only repair mode)")
        r = repair(args.oplog, apply=args.apply)
        print(json.dumps(r, ensure_ascii=False))
        for b in r["bad_lines"]:  # numbers and categories only, never the content
            print(f"  line {b['line']}: {b['category']}")
        if not r["bad_lines"]:
            print("  no bad lines")
        elif r["applied"]:
            print(
                f"  moved: torn tail -> {args.oplog}{TORN_SUFFIX}, other bad lines -> {args.oplog}{CORRUPT_SUFFIX}"
            )
        else:
            print("  dry run: nothing changed; add --apply to move these lines out of the op-log")
        return 0
    try:
        # verify-chain reads a chain file, not an op-log: never repair it, any bad
        # line is evidence of tampering, and the op-log schema version does not apply
        events = read_log(
            args.oplog, repair=args.cmd != "verify-chain", schema=args.cmd != "verify-chain"
        )
    except OplogError as e:
        if args.cmd == "verify-chain":
            sys.exit(f"TAMPER DETECTED at line {e.lineno}: not a JSON object ({e.category})")
        sys.exit(str(e))

    if args.cmd in ("attest", "verify-chain"):
        try:
            import amem_attest as _att
        except ImportError:
            sys.exit("attest requires amem_attest.py next to this file")
        _key = None
        if args.key:
            _key = args.key.encode("utf-8")
        elif args.keyfile:
            with open(args.keyfile, "rb") as f:
                _key = f.read().strip()
        elif os.environ.get("AMEM_ATTEST_KEY"):
            _key = os.environ["AMEM_ATTEST_KEY"].encode("utf-8")
        _mode = "HMAC-SHA256" if _key else "SHA-256"
        if args.cmd == "attest" and args.v2:
            try:
                r = attest_v2(args.oplog, out=args.out)
            except ChainMismatch as e:
                sys.exit(str(e))
            print(
                f"attest v2: {r['appended']} new entries -> {r['chain']} (last seq {r['last_seq']})"
            )
            print(f"head (commitment): {r['head']}")
            print("hashes only; keyed entries need <data dir>/.erasure_key to verify.")
            return 0
        if args.cmd == "verify-chain" and _att.is_v2(events):
            oplog = args.chain_oplog
            if not oplog and args.oplog.endswith(ATTEST_SUFFIX):
                oplog = args.oplog[: -len(ATTEST_SUFFIX)]
            if not oplog:
                sys.exit(
                    "an attest v2 chain is verified against its op-log: add --oplog <oplog.jsonl>"
                )
            try:
                r = verify_v2(args.oplog, oplog)
            except (OplogError, OSError, RuntimeError) as e:
                sys.exit(f"cannot verify {args.oplog} against {oplog}: {e}")
            if not r["ok"]:
                sys.exit("TAMPER DETECTED " + _chain_problem(args.oplog, oplog, r))
            print(
                f"VERIFIED — attest v2: {r['verified']} lines verified, {r['redacted']} redacted, "
                f"{r['unattested']} not yet attested; head={r['head']}"
            )
            return 0
        if args.cmd == "attest":
            out = args.out or (args.oplog + ".attest.jsonl")
            if os.path.exists(out) and _is_v2_chain_file(out):
                sys.exit(
                    f"{out} is an attest v2 chain; attest without --v2 would replace it with a v1 "
                    "chain. Run attest --v2 to extend it."
                )
            chain = _att.build_chain(events, _key)
            with open(out, "w", encoding="utf-8") as f:
                for e in chain:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            print(f"attested {len(chain)} events -> {out}  (mode: {_mode})")
            print(f"root (commitment): {_att.root_of(chain)}")
            print("tamper-EVIDENT, not tamper-PROOF — anchor this root externally (WORM/notary).")
        else:  # verify-chain: the positional file IS the chain
            ok, bad, reason = _att.verify_chain(events, _key)
            print(f"mode: {_mode}")
            if ok:
                print(f"VERIFIED — {reason}")
            else:
                sys.exit(f"TAMPER DETECTED at seq={bad}: {reason}")
        return 0

    if args.cmd == "list-quarantine":
        r = list_quarantine(args.oplog)
        print(json.dumps(r))
        for rid in r["quarantined"]:
            print(f"  {rid}")
        if not r["quarantined"]:
            print("  nothing is quarantined")
        return 0
    if args.cmd == "release":
        if not args.id:
            sys.exit("release needs --id <rid>")
        r = release(args.oplog, args.id)
        print(json.dumps(r))
        if r["released"] is None:
            sys.exit(r["reason"])
        print(f"  {r['released']} is re-certified as user and appears in recall again")
        return 0
    if args.cmd == "audit":
        rows = audit_timeline(events)
        if args.out:
            out, fmt = export(rows, args.out)
            print(f"exported {len(rows)} events -> {out} ({fmt})")
        else:
            _print_rows(rows)
    elif args.cmd == "summary":
        print(json.dumps(summary(events), indent=1, ensure_ascii=False))
    elif args.cmd == "lineage":
        if not args.id:
            sys.exit("--id required")
        for i, op, ev in lineage(events, args.id):
            print(
                f"  seq={i:<4} {op:<11} {json.dumps({k: v for k, v in ev.items() if k != 'op'}, ensure_ascii=False)[:100]}"
            )
    elif args.cmd == "conflicts":
        c = conflicts(events)
        print(f"{len(c)} contradiction(s):")
        for x in c:
            print(
                f"  a={x['a']}({x['a_status']}) b={x['b']}({x['b_status']}) why={x['why']} -> winner={x['winner']}"
            )
    elif args.cmd == "erase":
        if not args.match:
            sys.exit("--match <regex> required")
        try:
            record = erase(args.oplog, args.match, hard=args.hard, drop_attest=args.drop_attest)
        except re.error as e:
            sys.exit(f"invalid --match regex: {e}")
        except (OplogError, AttestPresent, ChainMismatch) as e:
            sys.exit(str(e))
        print(json.dumps(record, ensure_ascii=False, default=str))
        if not record["matched"]:  # never echo the pattern: it may be the text to erase
            print("  NO MATCH: no record matched --match; the op-log was not changed")
            if args.hard:
                print("  (post-purge hooks still run: a re-run finishes an earlier cleanup)")
        elif args.hard:
            print("  HARD PURGE (content removed)")
        else:
            print("  SOFT forget (auditable; text retained in log)")
        return _print_hooks(record, args.hard)
    elif args.cmd == "retention":
        try:
            record = retention(
                args.oplog,
                args.max_age_days,
                args.max_active,
                hard=args.hard,
                drop_attest=args.drop_attest,
            )
        except (OplogError, AttestPresent, ChainMismatch) as e:
            sys.exit(str(e))
        print(json.dumps(record, ensure_ascii=False, default=str))
        return _print_hooks(record, args.hard)
    return 0


def _ots_main(args):
    """export-digest, anchor-ots, upgrade-ots, verify-ots. Exit 0 ok, 1 refused or failed,
    3 (verify-ots) pending."""
    try:
        if args.cmd == "export-digest":
            if not args.oplog:
                sys.exit("usage: export-digest <chain.jsonl> [--out digest.txt]")
            r = export_digest(args.oplog, out=args.out)
            print(f"head {r['head']} (last seq {r['last_seq']}) -> {r['digest_file']}")
            print("anchor it on a machine with network access: anchor-ots --digest-file <file>")
            return 0
        if args.cmd == "anchor-ots":
            if not args.oplog and not args.digest_file:
                sys.exit(
                    "usage: anchor-ots (<chain.jsonl> | --digest-file F) [--calendar URL] [--allow-network]"
                )
            r = anchor_ots(
                args.oplog,
                digest_file=args.digest_file,
                out=args.out,
                calendars=args.calendar,
                timeout=args.timeout,
                allow_network=args.allow_network,
            )
            print(f"anchored head {r['head']} -> {r['proof']} ({len(r['calendars'])} calendar(s))")
            for err in r["errors"]:
                print(f"  calendar failed: {err}")
            if r["last_seq"] is None:
                print(f"  scope: {r['scope']}")
            else:
                print(
                    f"  scope: covers the chain up to last seq {r['last_seq']}; lines attested after it are "
                    "not covered until the next anchor"
                )
            print("  pending until a Bitcoin block includes it: run upgrade-ots later")
            return 0
        if args.cmd == "upgrade-ots":
            if not args.oplog:
                sys.exit("usage: upgrade-ots <proof.ots> [--calendar URL] [--allow-network]")
            r = upgrade_ots(
                args.oplog,
                calendars=args.calendar,
                timeout=args.timeout,
                allow_network=args.allow_network,
            )
            print(json.dumps(r))
            print(
                f"  Bitcoin attestation(s) at block {', '.join(map(str, r['bitcoin_heights']))}"
                if r["bitcoin_heights"]
                else "  still pending: no Bitcoin attestation yet"
            )
            return 0
        if not args.oplog or not (args.target or args.digest_file):
            sys.exit(
                "usage: verify-ots <proof.ots> (<chain.jsonl> | --digest-file F) [--bitcoin-node URL]"
            )
        r = verify_ots(
            args.oplog,
            args.target,
            digest_file=args.digest_file,
            bitcoin_node=args.bitcoin_node,
            btc_network=args.btc_network,
        )
        print(json.dumps(r))
        if r["status"] == "pending":
            print("  PENDING: no Bitcoin attestation yet (run upgrade-ots later)")
            return 3
        print(
            f"  VERIFIED: Bitcoin block {r['height']} attests the chain up to seq {r['covered_last_seq']}"
        )
        return 0
    except (OtsUnavailable, OtsError, ChainMismatch, OplogError, OSError) as e:
        sys.exit(str(e))


def _selftest():
    import tempfile

    p = os.path.join(tempfile.mkdtemp(prefix="gov_"), "ops.jsonl")
    t0 = time.time() - 100 * 86400
    evs = [
        {"op": "add", "id": "a", "text": "User works at Boeing.", "key": "job", "created_at": t0},
        {
            "op": "add",
            "id": "b",
            "text": "User works at SpaceX.",
            "key": "job",
            "created_at": t0 + 86400,
        },  # supersedes a
        {
            "op": "add",
            "id": "c",
            "text": "User SSN is 123-45-6789.",
            "key": "ssn",
            "created_at": t0 + 2 * 86400,
        },
        {
            "op": "update",
            "id": "c",
            "text": "User SSN is 123-45-6789 (verified).",
            "created_at": t0 + 3 * 86400,
        },
        {"op": "flag", "a": "a", "b": "b", "why": "neg"},
        {
            "op": "add",
            "id": "d",
            "text": "User likes jazz.",
            "key": "music",
            "created_at": time.time(),
        },
    ]
    with open(p, "w", encoding="utf-8") as f:
        for e in evs:
            f.write(json.dumps(e) + "\n")

    events = read_log(p)
    rec, _ = replay(events)
    assert rec["a"]["status"] == "superseded" and rec["b"]["status"] == "active", (
        "same-key supersede"
    )
    assert "verified" in rec["c"]["text"], "update applied"

    rows = audit_timeline(events)
    assert len(rows) == 6 and rows[0]["op"] == "add", "audit timeline"
    out, fmt = export(rows, p + ".csv")
    assert os.path.exists(out)

    c = conflicts(events)
    assert c and c[0]["winner"] == "b", f"conflict winner should be active side: {c}"

    lin = lineage(events, "a")
    assert any(op == "add" for _, op, _ in lin), "lineage has birth"

    # GDPR soft erase: SSN forgotten but text retained in the log (auditable)
    record = erase(p, "SSN", hard=False)
    assert record["matched"] == 1 and record["mode"] == "soft", record
    assert any("SSN" in (e.get("text") or "") for e in read_log(p)), "soft: text retained for audit"
    rec2, _ = replay(read_log(p))
    assert rec2["c"]["status"] == "deleted", "soft: status deleted"

    # GDPR hard purge: SSN content removed from the log entirely
    record = erase(p, "SSN", hard=True)
    assert record["mode"] == "hard", record
    assert not any("123-45-6789" in (e.get("text") or "") for e in read_log(p)), (
        "hard: content gone"
    )
    assert any(e.get("op") == "purge" for e in read_log(p)), "hard: purge action logged"

    # retention by age: the 100-day-old active record(s) retired
    record = retention(p, max_age_days=30, hard=False)
    assert record["retired"] >= 1, record

    # integration: attest the op-log, verify passes; mutate one byte, verify fails
    try:
        import amem_attest as _att

        _ev = read_log(p)
        _chain = _att.build_chain(_ev, None)
        _ok, _, _ = _att.verify_chain(_chain, None)
        assert _ok, "attest integration: fresh chain must verify"
        _chain[0]["payload"]["text"] = "tampered"
        _ok, _bad, _ = _att.verify_chain(_chain, None)
        assert (not _ok) and _bad == 0, "attest integration: tamper must be detected at seq 0"
    except ImportError:
        print("  (amem_attest not present — integration check skipped)")

    print(
        "SELFTEST PASS: replay+supersede, audit export, conflict winner, lineage, "
        "GDPR soft-forget (retained) vs hard-purge (removed), retention. (no amem/GPU/API)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
