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
  python amem_governance.py verify-chain <chain.jsonl> [--key K|--keyfile F]
  python amem_governance.py repair --quarantine-bad-lines <oplog.jsonl> [--apply]
  python amem_governance.py --selftest

Hard purge (erase --hard, retention --hard): removes the record's lines, every event naming
it, matching lines of <oplog>.torn and <oplog>.corrupt, and its .vec lines; the purge marker
holds HMAC-SHA256 of the erase pattern with <data dir>/.erasure_key (created on first need,
mode 0600, never deleted by erase or retention; back it up with the data directory, or
existing HMACs can no longer be checked; markers written before hold a plain SHA-256 and are
left as they are). It refuses while <oplog>.attest.jsonl exists, because that chain stores
every event verbatim; --drop-attest deletes the chain file first. Chains written elsewhere
with --out are not checked.
Post-purge hooks: after every HARD erase/retention, each installed entry point
in the group "atelya.purge_hooks" is called with the op-log path, the purged
record ids with SHA-256 digests of their texts, and (erase only) the matcher.
Hooks never receive the erased text. The CLI prints every hook and its
outcome, or a line saying none is installed; a failed hook exits 1.

Exit codes (erase, retention): 0 on success, including when nothing matched
or nothing was due. Erasure is idempotent: re-running after a failed hook is
expected to match nothing. 1 means a post-purge hook failed. To know whether
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
import errno
import hashlib
import hmac
import json
import logging
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


def _load_lines(path, repair=True):
    """[(lineno, raw bytes, event or None for a blank line)] for every line, read
    under the lock. repair: move a torn tail to <path>.torn first; without it (or
    in a read-only directory) a torn tail raises like any other bad line."""
    if not os.path.exists(path):
        raise FileNotFoundError(errno.ENOENT, "op-log not found", path)
    with oplog_lock(path, readonly_ok=True) as locked:
        with open(path, "rb") as f:
            data = f.read()
        if repair and data and not data.endswith(b"\n"):
            start = data.rfind(b"\n") + 1
            if classify(data[start:])[0] is not None:
                if not locked:
                    raise OplogError(path, data.count(b"\n") + 1, "torn_tail")
                with open(path, "rb+") as f:
                    _fix_tail(path, f, keep_torn=True)
                    f.seek(0)
                    data = f.read()
    pieces = data.split(b"\n")
    terminated = data.endswith(b"\n") or not data
    if terminated:
        pieces = pieces[:-1]
    out = []
    for i, raw in enumerate(pieces, 1):
        cat, ev = classify(raw)
        if cat == "blank":
            out.append((i, raw, None))
            continue
        if cat is not None:
            if i == len(pieces) and not terminated:
                cat = "torn_tail"
            raise OplogError(path, i, cat)
        out.append((i, raw, ev))
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


def read_events(path, repair=True):
    """[(lineno, event)] for every non-blank line, as written (no legacy promotion)."""
    return [(n, ev) for n, _raw, ev in _load_lines(path, repair) if ev is not None]


def read_log(path, repair=True):
    return [_promote(ev) for _n, ev in read_events(path, repair)]


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
                "created_at": ev.get("created_at"),
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
        ts = ev.get("created_at")
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


def _attest_guard(path, drop_attest):
    """Refuse a hard purge while the default attest chain exists: it stores every
    event verbatim, so the purged text would stay in it. drop_attest deletes it.
    Returns True when it was deleted. Chain files written elsewhere (--out) are
    not checked."""
    chain = path + ATTEST_SUFFIX
    if not os.path.exists(chain):
        return False
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
    """(kept raw lines, {id: [texts]}, ids kept) for a hard purge of `targets`.
    Dropped: the add line of each target (an id-less old-format line by its replay
    id), every event naming a target in REF_FIELDS, and every old key_conflict (no
    id, written before ids were added to it) whose text excerpt is a prefix of a
    purged text, with no minimum length. Every other line is kept unchanged."""
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
    purged = [t for ts in texts.values() for t in ts if t]
    kept, kept_ids = [], set()
    for i, (_n, raw, ev) in enumerate(lines):
        if ev is not None:
            if rids[i] in targets:
                continue
            if any(isinstance(ev.get(f), str) and ev.get(f) in targets for f in REF_FIELDS):
                continue
            ex = ev.get("text")  # only old key_conflict events carry one
            if (
                ev.get("op") == "key_conflict"
                and isinstance(ex, str)
                and ex
                and any(t.startswith(ex) for t in purged)
            ):
                continue
            if rids[i] is not None:
                kept_ids.add(rids[i])
        kept.append(raw)
    return kept, texts, kept_ids


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
    text_forms. Returns the number of lines dropped. Caller holds the lock."""
    forms = [f for t in texts for f in text_forms(t)]
    if not forms:
        return 0
    windows = {f[i : i + _WINDOW] for f in forms for i in range(len(f) - _WINDOW + 1)}
    dropped = 0
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
            if _holds_purged(line, forms, windows):
                dropped += 1
            else:
                kept.append(raw)
        if len(kept) == len(pieces):
            continue
        if not kept:
            os.remove(side)
            continue
        tmp = side + ".tmp"
        with open(tmp, "wb") as f:
            for raw in kept:
                f.write(raw + b"\n")
        os.replace(tmp, side)
    return dropped


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
    with oplog_lock(path):
        attest_dropped = _attest_guard(path, drop_attest) if hard else False
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
                        {
                            "op": "forget",
                            "id": rid,
                            "reason": f"erasure:/{pattern}/",
                            "created_at": time.time(),
                        }
                    )
                    for rid in targets
                ],
            )
            _bump_epoch(path)  # F3c
            return {"matched": len(targets), "mode": "soft", "ids": sorted(targets)}
        n_vec, n_side, digests = 0, 0, {}
        if targets:
            kept, texts, kept_ids = _purge_plan(lines, targets)
            mark = "erasure:hmac-sha256:" + _hmac_hex(path, pattern)
            markers = [
                {
                    "op": "purge",
                    "id": _marker_id(rid),
                    "reason": mark,
                    "created_at": time.time(),
                    "note": "content removed for compliance",
                }
                for rid in sorted(targets)
            ]
            _rewrite(path, kept, markers)
            _bump_epoch(path)  # F3c
            n_vec = _purge_vec(path, targets, keep_ids=kept_ids)  # F3a: the embeddings too
            n_side = _scrub_side_files(path, [t for ts in texts.values() for t in ts])
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
            "side_lines_purged": n_side,
            "hooks": hooks,
        }
    if attest_dropped:
        out["attest_dropped"] = True
    return out


def retention(path, max_age_days=None, max_active=None, hard=False, drop_attest=False):
    """Retire by age and/or active-count window. A hard purge follows the same rules
    as a hard erase (_purge_plan, side files, attest guard). The read and the write
    hold <path>.lock; a hard purge keeps every other line byte for byte; hooks run
    after the lock is released."""
    with oplog_lock(path):
        attest_dropped = _attest_guard(path, drop_attest) if hard else False
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
        digests = {}
        if not doomed:
            if not hard:
                return {"retired": 0, "mode": "soft"}
        elif hard:
            gone = set(doomed)
            kept, texts, kept_ids = _purge_plan(lines, gone)
            markers = [
                {"op": "purge", "id": _marker_id(rid), "reason": "retention", "created_at": now}
                for rid in doomed
            ]
            _rewrite(path, kept, markers)
            _bump_epoch(path)  # F3c
            _purge_vec(path, gone, keep_ids=kept_ids)  # F3a: the embeddings too
            _scrub_side_files(path, [t for ts in texts.values() for t in ts])
            digests = {rid: _digests(ts) for rid, ts in texts.items()}
        else:
            _append_lines(
                path,
                [
                    json.dumps(
                        {"op": "forget", "id": rid, "reason": "retention", "created_at": now}
                    )
                    for rid in doomed
                ],
            )
            _bump_epoch(path)  # F3c
            return {"retired": len(doomed), "mode": "soft", "ids": doomed}
    hooks = run_purge_hooks(path, digests, None)
    out = {"retired": 0, "mode": "hard", "hooks": hooks}
    if doomed:
        out = {"retired": len(doomed), "mode": "hard", "ids": doomed, "hooks": hooks}
    if attest_dropped:
        out["attest_dropped"] = True
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
        print(
            f"  post-purge hooks: none installed (entry-point group {PURGE_HOOK_GROUP!r}); "
            + (
                "only the op-log and its .vec sidecar were purged"
                if purged
                else "nothing was purged"
            )
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
        ],
    )
    parser.add_argument("oplog", nargs="?")
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
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()
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
        # verify-chain reads a chain file, not an op-log: never repair it, and any
        # bad line is evidence of tampering
        events = read_log(args.oplog, repair=args.cmd != "verify-chain")
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
        if args.cmd == "attest":
            chain = _att.build_chain(events, _key)
            out = args.out or (args.oplog + ".attest.jsonl")
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
        except (OplogError, AttestPresent) as e:
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
        except (OplogError, AttestPresent) as e:
            sys.exit(str(e))
        print(json.dumps(record, ensure_ascii=False, default=str))
        return _print_hooks(record, args.hard)
    return 0


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
