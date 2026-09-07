#!/usr/bin/env python3
"""amem_governance.py — enterprise governance over amem's append-only op-log.

The market's #1 unmet need for agent memory (multiple 2026 surveys): "Can memories be audited?
How are conflicting memories resolved? What's the retention/deletion policy?" amem already
event-sources every operation into an append-only JSONL op-log; this module turns that into the
governance FEATURES enterprises require — without touching the core.

Op-log events (amem memory.py): {"op":"add","id","text","key","created_at"} | {"op":"update",...}
| {"op":"supersede","id"} | {"op":"forget","id"} | {"op":"key_conflict",...} | {"op":"flag","a","b","why"}.
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
  python amem_governance.py erase   <oplog.jsonl> --match <regex> [--hard]
  python amem_governance.py retention <oplog.jsonl> --max-age-days N [--hard]
  python amem_governance.py attest    <oplog.jsonl> [--out chain.jsonl] [--key K|--keyfile F]
  python amem_governance.py verify-chain <chain.jsonl> [--key K|--keyfile F]
  python amem_governance.py --selftest

Integrity (attest — hash-chain the op-log): SHA-256 (or HMAC-SHA256 with a key) chain per
the 2026 audit-trail pattern (arXiv 2601.20727; NIST SP 800-92). Tamper-EVIDENT, not
tamper-PROOF: any modification/deletion/reorder is detected and located; anchor the printed
root externally (WORM/notary) for full assurance.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
import signal


def read_log(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (
                ValueError
            ):  # malformed / non-JSON line -> skip (JSONDecodeError is a ValueError)
                continue
            if "op" not in ev and "text" in ev:  # legacy {"text":...} == add
                ev = {
                    "op": "add",
                    "text": ev["text"],
                    "id": ev.get("id"),
                    "key": ev.get("key"),
                    "created_at": ev.get("created_at"),
                }
            out.append(ev)
    return out


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


def _purge_vec(oplog_path, ids):
    """F3a: drop erased records from the `<oplog>.vec` sidecar.

    The sidecar caches one embedding per record. A hard erasure that rewrites the
    op-log but leaves the sidecar behind is NOT a complete erasure: embeddings are
    approximately invertible back to text. Returns the number of lines removed.
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
                if json.loads(s).get("id") in targets:
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


def erase(path, pattern, hard=False):
    """GDPR right-to-erasure. soft: append forget events (auditable, text retained).
    hard: rewrite the log dropping the matched records' content entirely; log a purge marker."""
    events = read_log(path)
    targets = set(_match_ids(events, pattern))
    if not targets:
        return {"matched": 0, "mode": "hard" if hard else "soft", "ids": []}
    if not hard:
        with open(path, "a", encoding="utf-8") as f:
            for rid in targets:
                f.write(
                    json.dumps(
                        {
                            "op": "forget",
                            "id": rid,
                            "reason": f"erasure:/{pattern}/",
                            "created_at": time.time(),
                        }
                    )
                    + "\n"
                )
        return {"matched": len(targets), "mode": "soft", "ids": sorted(targets)}
    # hard purge: filter out add/update/supersede/forget for targets; keep a purge audit marker
    kept = [
        ev
        for ev in events
        if ev.get("id") not in targets and ev.get("a") not in targets and ev.get("b") not in targets
    ]
    for rid in sorted(targets):
        kept.append(
            {
                "op": "purge",
                "id": rid,
                "reason": "erasure:sha256:" + hashlib.sha256(pattern.encode()).hexdigest(),
                "created_at": time.time(),
                "note": "content removed for compliance",
            }
        )
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for ev in kept:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    os.replace(tmp, path)
    n_vec = _purge_vec(path, targets)  # F3a: erase the embeddings too
    return {"matched": len(targets), "mode": "hard", "ids": sorted(targets), "vec_purged": n_vec}


def retention(path, max_age_days=None, max_active=None, hard=False):
    events = read_log(path)
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
    if not doomed:
        return {"retired": 0, "mode": "hard" if hard else "soft"}
    if hard:
        kept = [ev for ev in events if ev.get("id") not in set(doomed)]
        for rid in doomed:
            kept.append({"op": "purge", "id": rid, "reason": "retention", "created_at": now})
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for ev in kept:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
        _purge_vec(path, set(doomed))  # F3a: erase the embeddings too
    else:
        with open(path, "a", encoding="utf-8") as f:
            for rid in doomed:
                f.write(
                    json.dumps(
                        {"op": "forget", "id": rid, "reason": "retention", "created_at": now}
                    )
                    + "\n"
                )
    return {"retired": len(doomed), "mode": "hard" if hard else "soft", "ids": doomed}


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
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()
    if not args.cmd or not args.oplog:
        sys.exit(
            "usage: amem_governance.py {audit|lineage|conflicts|erase|retention|summary} <oplog.jsonl> [...]"
        )
    if not os.path.exists(args.oplog):
        sys.exit(f"op-log not found: {args.oplog}")
    events = read_log(args.oplog)

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
            record = erase(args.oplog, args.match, hard=args.hard)
        except re.error as e:
            sys.exit(f"invalid --match regex: {e}")
        print(json.dumps(record, ensure_ascii=False))
        print(
            f"  {'HARD PURGE (content removed)' if args.hard else 'SOFT forget (auditable; text retained in log)'}"
        )
    elif args.cmd == "retention":
        record = retention(args.oplog, args.max_age_days, args.max_active, hard=args.hard)
        print(json.dumps(record, ensure_ascii=False))
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
