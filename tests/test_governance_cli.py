"""The atelya-govern, atelya-attest and atelya-anchor command lines on every
supported Python.

1. Every documented command form runs and does its job. The forms are
   extracted, not copied: from the docs of this repo that exist among DOCS,
   the usage blocks of amem_governance.py, amem_attest.py and amem_anchor.py,
   and the repair command printed by the op-log load error (amem_governance,
   and amem.oplog where the package is in the repo). Optional [parts] are
   expanded. Each form runs as a subprocess on temp files.
2. Options between the subcommand and the path work too (a few undocumented
   orders).
3. A hard purge without post-purge hooks names every file it cleaned.
4. The governance exit codes are the ones its usage text documents.

With parser.parse_args, argparse on Python 3.10, 3.11, 3.12.0-3.12.6 and
3.13.0 matched an optional positional to zero strings before an option and
then rejected the path as "unrecognized arguments" (exit 2), so
`repair --quarantine-bad-lines <oplog>` and every other form with an option
before the path failed there. parse_intermixed_args parses optionals first.

This file is identical in atelya-internal and atelya-public.
"""

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import amem_anchor  # noqa: E402
import amem_attest  # noqa: E402
import amem_governance as gov  # noqa: E402

DOCS = [
    "README.md",
    "ATTESTATION.md",
    "docs/PRIVATE-QUICKSTART.md",
    "ATELYA-COMPLIANCE-ONEPAGER-EN.md",
]
TOOLS = {
    "govern": {
        "script": "amem_governance.py",
        "program": r"(?:atelya-govern|amem_governance\.py)",
        "module": gov,
        "cmds": {
            "audit",
            "lineage",
            "conflicts",
            "erase",
            "retention",
            "summary",
            "attest",
            "verify-chain",
            "repair",
        },
        "values": {
            "--id",
            "--match",
            "--out",
            "--max-age-days",
            "--max-active",
            "--key",
            "--keyfile",
            "--oplog",
        },
        "flags": {
            "--hard",
            "--selftest",
            "--quarantine-bad-lines",
            "--apply",
            "--drop-attest",
            "--v2",
            "--help",
        },
        "no_path": set(),
    },
    "attest": {
        "script": "amem_attest.py",
        "program": r"(?:atelya-attest|amem_attest\.py)",
        "module": amem_attest,
        "cmds": {"attest", "verify", "root"},
        "values": {"--out", "--key", "--keyfile"},
        "flags": {"--selftest", "--help"},
        "no_path": set(),
    },
    "anchor": {
        "script": "amem_anchor.py",
        "program": r"(?:atelya-anchor|amem_anchor\.py)",
        "module": amem_anchor,
        "cmds": {"anchor", "check", "latest"},
        "values": {
            "--ledger",
            "--label",
            "--key",
            "--keyfile",
            "--chain-key",
            "--chain-keyfile",
            "--at",
        },
        "flags": {"--require-anchor", "--selftest", "--help"},
        "no_path": {"latest"},
    },
}
KEY = "test-key-not-a-secret"
RECORDS = [
    {"op": "add", "id": "r1", "text": "walrus secret plan alpha", "created_at": 1718000000},
    {"op": "add", "id": "r2", "text": "keeper fact beta", "created_at": 1718000001},
]


# ----------------------------- extracting the documented forms -----------------------------
def _split_top(text, sep):
    parts, depth, cur = [], 0, ""
    for c in text:
        depth += (c == "[") - (c == "]")
        if c == sep and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    return parts + [cur]


def _expand(text):
    """Every concrete variant of a usage string. [--a X|--b Y] is a choice of
    options, [--out a.json|a.csv] a choice of values; groups nest."""
    i = text.find("[")
    if i < 0:
        return [" ".join(text.split())]
    depth = 0
    for j in range(i, len(text)):
        depth += (text[j] == "[") - (text[j] == "]")
        if depth == 0:
            break
    head, inner, tail = text[:i], text[i + 1 : j], text[j + 1 :]
    alts = [a.strip() for a in _split_top(inner, "|")]
    if not all(a.startswith("-") for a in alts):
        stem = alts[0].rsplit(" ", 1)[0]
        alts = [alts[0]] + [f"{stem} {a}" for a in alts[1:]]
    out = []
    for choice in [""] + alts:
        for c in _expand(choice):
            for t in _expand(tail):
                out.append(" ".join(f"{head} {c} {t}".split()))
    return out


def _cut(rest):
    """The command text up to the first shell or markdown terminator outside [brackets]."""
    depth = 0
    for i, c in enumerate(rest):
        depth += (c == "[") - (c == "]")
        if depth:
            continue
        prev = rest[i - 1] if i else " "
        if (
            c in "`;)|"
            or rest.startswith("&&", i)
            or (c == "#" and prev.isspace())
            or (c == ">" and (prev.isspace() or prev.isdigit()))
        ):
            return rest[:i].strip()
    return rest.strip()


def _shape(tool, cmdline):
    """A tuple like ("repair", "--quarantine-bad-lines", "P"): positionals become
    "P", value options become (option, None), except --out, which keeps its file
    suffix. None when the text is not a command (prose that names the tool)."""
    t = TOOLS[tool]
    try:
        toks = shlex.split(cmdline)
    except ValueError:
        return None
    if not toks or not (toks[0] in t["cmds"] or toks[0].startswith("--")):
        return None
    shape, k = [], 0
    while k < len(toks):
        tok = toks[k]
        if k == 0 and tok in t["cmds"]:
            shape.append(tok)
        elif tok.startswith("--"):
            opt, eq, val = tok.partition("=")
            if opt in t["values"]:
                if not eq:
                    k += 1
                    val = toks[k] if k < len(toks) else ""
                shape.append((opt, Path(val).suffix or ".out") if opt == "--out" else (opt, None))
            elif opt in t["flags"]:
                shape.append(opt)
            else:
                raise AssertionError(f"unknown {tool} option {tok!r} in a documented form")
        elif tok == "/":  # "atelya-anchor anchor / check / latest" names commands in prose
            return None
        else:
            shape.append("P")
        k += 1
    return tuple(shape)


def _runnable(tool, shape):
    """A subcommand without its path ("atelya-govern attest" in a table) is a mention."""
    return shape[0] not in TOOLS[tool]["cmds"] or "P" in shape or shape[0] in TOOLS[tool]["no_path"]


def _bad_oplog(path):
    lines = [json.dumps(RECORDS[0]), "not json", json.dumps(RECORDS[1])]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load_error_messages():
    """The op-log load errors, which tell the user which repair command to run."""
    msgs = []
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "bad.jsonl")
        _bad_oplog(bad)
        with pytest.raises(gov.OplogError) as e:
            gov.read_log(bad)
        msgs.append(("amem_governance load error", str(e.value)))
        if (REPO / "amem" / "oplog.py").exists():
            import amem.oplog as oplog

            with pytest.raises(oplog.OplogError) as e:
                oplog.read_events(bad)
            msgs.append(("amem.oplog load error", str(e.value)))
    return msgs


def _usage_lines(tool):
    """(line number, text) of each usage line in the module docstring, with its
    indented [continuation] lines joined on."""
    out = []
    pattern = re.compile(rf"(\s*)python3? {re.escape(TOOLS[tool]['script'])} (.*)$")
    lines = (TOOLS[tool]["module"].__doc__ or "").splitlines()
    for n, line in enumerate(lines, 1):
        m = pattern.match(line)
        if not m:
            continue
        text, indent = m.group(2), len(m.group(1))
        for more in lines[n:]:
            if more.strip().startswith("[") and len(more) - len(more.lstrip()) > indent:
                text += " " + more.strip()
            else:
                break
        out.append((n, text))
    return out


def documented_forms():
    """{(tool, shape): [sources]} for every documented command form."""
    forms = {}

    def add(tool, source, text):
        for variant in _expand(text):
            s = _shape(tool, variant)
            if s and _runnable(tool, s):
                forms.setdefault((tool, s), []).append(source)

    for rel in DOCS:
        path = REPO / rel
        if not path.exists():
            continue
        joined, buf, start = [], "", None
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            start = start or n
            if line.rstrip().endswith("\\"):
                buf += line.rstrip()[:-1] + " "
                continue
            joined.append((start, buf + line))
            buf, start = "", None
        for n, line in joined:
            for tool, t in TOOLS.items():
                for m in re.finditer(t["program"] + r"(?=[\s`]|$)", line):
                    add(tool, f"{rel}:{n}", _cut(line[m.end() :]))
    for tool in TOOLS:
        for n, text in _usage_lines(tool):
            add(tool, f"{TOOLS[tool]['script']} usage line {n}", text)
    for source, msg in _load_error_messages():
        m = re.search(r"atelya-govern (.*?) \(then add (--[\w-]+)", msg)
        assert m, f"{source} names no repair command: {msg}"
        add("govern", source, m.group(1))
        add("govern", f"{source} (+{m.group(2)})", f"{m.group(1)} {m.group(2)}")
    return forms


FORMS = documented_forms()
INTERLEAVED = [
    ("govern", ("erase", "--hard", "P", ("--match", None))),
    ("govern", ("erase", ("--match", None), "P")),
    ("govern", ("retention", ("--max-active", None), "P", "--hard")),
    ("govern", ("attest", ("--out", ".jsonl"), "P")),
    ("govern", ("audit", ("--out", ".csv"), "P")),
    ("govern", ("lineage", ("--id", None), "P")),
    ("govern", ("repair", "--apply", "--quarantine-bad-lines", "P")),
    ("attest", ("attest", ("--out", ".jsonl"), "P")),
    ("attest", ("verify", ("--key", None), "P")),
    ("anchor", ("anchor", ("--ledger", None), ("--label", None), "P")),
    ("anchor", ("check", ("--ledger", None), "P", ("--label", None))),
    ("anchor", ("check", "--require-anchor", "P", ("--ledger", None))),
]


def _label(tool, shape):
    words = (x if isinstance(x, str) else f"{x[0]} {x[1] or 'V'}" for x in shape)
    return f"{tool}: " + " ".join(words)


# ----------------------------- running a form -----------------------------
def _write_oplog(path):
    Path(path).write_text("".join(json.dumps(r) + "\n" for r in RECORDS), encoding="utf-8")


def _env():
    env = dict(os.environ)
    for name in ("AMEM_ATTEST_KEY", "AMEM_ANCHOR_KEY"):
        env.pop(name, None)
    env["PYTHONUTF8"] = "1"
    return env


def _run(tool, argv, cwd):
    return subprocess.run(
        [sys.executable, str(REPO / TOOLS[tool]["script"]), *argv],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        env=_env(),
    )


def _ok(res):
    assert res.returncode == 0, f"setup step failed: rc {res.returncode} {res.stderr[-400:]}"


def _opts(shape):
    return {item[0] for item in shape if isinstance(item, tuple)}


def _keyfile(d):
    keyfile = os.path.join(d, "test.key")
    Path(keyfile).write_text(KEY, encoding="utf-8")
    return keyfile


def _key_args(
    opts, keyfile, key="--key", keyfile_opt="--keyfile", as_key="--key", as_file="--keyfile"
):
    if key in opts:
        return [as_key, KEY]
    if keyfile_opt in opts:
        return [as_file, keyfile]
    return []


def _fill(shape, path, values):
    argv = []
    for item in shape:
        if item == "P":
            argv.append(path)
        elif isinstance(item, tuple):
            argv += [item[0], values[item[0]]]
        else:
            argv.append(item)
    return argv


def _concrete(tool, shape, d):
    """argv for a shape, on fresh files in d, and what the run must show."""
    cmd = shape[0] if shape[0] in TOOLS[tool]["cmds"] else None
    oplog = os.path.join(d, "log.jsonl")
    (_bad_oplog if (tool, cmd) == ("govern", "repair") else _write_oplog)(oplog)
    keyfile, opts = _keyfile(d), _opts(shape)
    out_suffix = next((x[1] for x in shape if isinstance(x, tuple) and x[0] == "--out"), "")
    out_file = os.path.join(d, "out" + out_suffix) if "--out" in opts else None
    values = {"--out": out_file, "--key": KEY, "--keyfile": keyfile}
    ctx = {"tool": tool, "cmd": cmd, "oplog": oplog, "out": out_file, "apply": "--apply" in shape}
    chain = os.path.join(d, "prebuilt.chain.jsonl")
    if tool == "govern":
        if cmd == "verify-chain":
            _ok(_run("govern", ["attest", oplog, "--out", chain, *_key_args(opts, keyfile)], d))
        values.update(
            {
                "--id": "r1",
                "--match": "walrus",
                "--max-age-days": "36500",
                "--max-active": "10",
                "--oplog": oplog,
            }
        )
        return _fill(shape, chain if cmd == "verify-chain" else oplog, values), ctx
    if tool == "attest":
        if cmd in ("verify", "root"):
            _ok(_run("attest", ["attest", oplog, "--out", chain, *_key_args(opts, keyfile)], d))
        return _fill(shape, oplog if cmd == "attest" else chain, values), ctx
    # anchor: the ledger key (--key/--keyfile) and the chain key (--chain-key/...) are separate
    chain_for_attest = _key_args(opts, keyfile, "--chain-key", "--chain-keyfile")
    chain_for_anchor = _key_args(
        opts, keyfile, "--chain-key", "--chain-keyfile", "--chain-key", "--chain-keyfile"
    )
    _ok(_run("attest", ["attest", oplog, "--out", chain, *chain_for_attest], d))
    ledger = os.path.join(d, "ledger.jsonl")
    label = ["--label", "prod"] if "--label" in opts else []
    if cmd in ("check", "latest"):
        anchor_argv = ["anchor", chain, "--ledger", ledger, *label]
        _ok(_run("anchor", anchor_argv + _key_args(opts, keyfile) + chain_for_anchor, d))
    values.update(
        {
            "--ledger": ledger,
            "--label": "prod",
            "--chain-key": KEY,
            "--chain-keyfile": keyfile,
            "--at": "2026-01-01T00:00:00Z",
        }
    )
    ctx["ledger"] = ledger
    return _fill(shape, chain, values), ctx


def _check_did_its_job(res, ctx):
    tool, cmd, out = ctx["tool"], ctx["cmd"], res.stdout
    first = out.splitlines()[0] if out.strip() else ""
    if cmd is None:  # --selftest, --help
        return
    if tool == "govern" and cmd == "erase":
        assert json.loads(first)["matched"] == 1, out
    elif tool == "govern" and cmd == "retention":
        assert "retired" in json.loads(first), out
    elif cmd == "attest":
        assert os.path.getsize(ctx["out"] or ctx["oplog"] + ".attest.jsonl") > 0
    elif cmd in ("verify-chain", "verify"):
        assert "VERIFIED" in out, out
    elif cmd == "root":
        assert re.search(r"\b[0-9a-f]{64}\b", out), out
    elif cmd == "repair":
        assert "line 2: invalid_json" in out, out
        if ctx["apply"]:
            assert "not json" not in Path(ctx["oplog"]).read_text(encoding="utf-8")
            assert os.path.exists(ctx["oplog"] + ".corrupt")
    elif cmd == "audit":
        assert os.path.getsize(ctx["out"]) > 0 if ctx["out"] else out.strip(), out
    elif cmd == "lineage":
        assert "r1" in out, out
    elif cmd == "anchor":
        assert len(Path(ctx["ledger"]).read_text(encoding="utf-8").splitlines()) == 1
    elif cmd == "latest":
        assert '"root"' in out, out


def _run_form(tool, shape, tmp_path):
    argv, ctx = _concrete(tool, shape, str(tmp_path))
    res = _run(tool, argv, str(tmp_path))
    msg = (
        f"argv {argv}\nrc {res.returncode}\nstdout {res.stdout[-600:]}\nstderr {res.stderr[-600:]}"
    )
    assert "unrecognized arguments" not in res.stderr, msg
    assert res.returncode == 0, msg
    _check_did_its_job(res, ctx)


@pytest.mark.parametrize(
    "tool,shape",
    [
        pytest.param(tool, s, id=f"{_label(tool, s)} [{src[0]}]")
        for (tool, s), src in sorted(FORMS.items(), key=str)
    ],
)
def test_documented_form_runs(tool, shape, tmp_path):
    _run_form(tool, shape, tmp_path)


@pytest.mark.parametrize(
    "tool,shape", [pytest.param(tool, s, id=_label(tool, s)) for tool, s in INTERLEAVED]
)
def test_option_before_the_path_runs(tool, shape, tmp_path):
    _run_form(tool, shape, tmp_path)


def test_extraction_finds_the_forms_users_are_told_to_run():
    repair = ("govern", ("repair", "--quarantine-bad-lines", "P"))
    assert repair in FORMS and ("govern", repair[1] + ("--apply",)) in FORMS
    assert any(s.startswith("amem_governance load error") for s in FORMS[repair])
    assert any("usage line" in s for s in FORMS[repair])
    assert ("govern", ("--selftest",)) in FORMS
    assert ("attest", ("attest", "P")) in FORMS and ("attest", ("verify", "P")) in FORMS
    assert ("anchor", ("latest", ("--ledger", None))) in FORMS
    assert ("anchor", ("check", "P", ("--ledger", None), "--require-anchor")) in FORMS
    counts = {tool: sum(1 for t, _s in FORMS if t == tool) for tool in TOOLS}
    assert counts["govern"] >= 20 and counts["attest"] >= 8 and counts["anchor"] >= 40, counts


# ----------------------------- the purge names what it cleaned -----------------------------
def _store_with_side_files(d):
    p = os.path.join(d, "log.jsonl")
    _write_oplog(p)
    with open(p + ".vec", "w", encoding="utf-8") as f:
        for rid in ("r1", "r2"):
            f.write(json.dumps({"id": rid, "model": "md5-test", "vec": [0.5, 0.5]}) + "\n")
    with open(p + ".torn", "w", encoding="utf-8") as f:
        f.write(json.dumps(RECORDS[0])[:40] + "\n")
    with open(p + ".corrupt", "w", encoding="utf-8") as f:
        f.write("7\t" + json.dumps(RECORDS[0]) + "\n")
    return p


def _no_hook_line(rec, capsys):
    capsys.readouterr()
    rec = dict(rec, hooks=[])
    assert gov._print_hooks(rec, True) == 0
    return capsys.readouterr().out


def test_hard_erase_names_every_file_it_cleaned(tmp_path, capsys):
    p = _store_with_side_files(str(tmp_path))
    rec = gov.erase(p, "walrus", hard=True)
    names = ["log.jsonl", "log.jsonl.vec", "log.jsonl.torn", "log.jsonl.corrupt"]
    assert rec["cleaned"] == names, rec
    out = _no_hook_line(rec, capsys)
    assert "cleaned only " + ", ".join(names) in out, out
    assert "its .vec sidecar" not in out, out


def test_hard_erase_without_side_files_names_only_the_oplog(tmp_path, capsys):
    p = os.path.join(str(tmp_path), "log.jsonl")
    _write_oplog(p)
    rec = gov.erase(p, "walrus", hard=True)
    assert rec["cleaned"] == ["log.jsonl"], rec
    assert "cleaned only log.jsonl\n" in _no_hook_line(rec, capsys)


def test_hard_retention_names_the_files_and_the_dropped_chain(tmp_path, capsys):
    p = _store_with_side_files(str(tmp_path))
    assert _run("govern", ["attest", p], str(tmp_path)).returncode == 0
    rec = gov.retention(p, max_active=1, hard=True, drop_attest=True)
    names = [
        "log.jsonl",
        "log.jsonl.vec",
        "log.jsonl.torn",
        "log.jsonl.corrupt",
        "log.jsonl.attest.jsonl",
    ]
    assert rec["retired"] == 1 and rec["cleaned"] == names, rec
    assert "cleaned only " + ", ".join(names) in _no_hook_line(rec, capsys)


def test_nothing_matched_but_chain_dropped_says_so(tmp_path, capsys):
    p = os.path.join(str(tmp_path), "log.jsonl")
    _write_oplog(p)
    assert _run("govern", ["attest", p], str(tmp_path)).returncode == 0
    rec = gov.erase(p, "no-such-text", hard=True, drop_attest=True)
    assert rec["matched"] == 0 and rec["cleaned"] == ["log.jsonl.attest.jsonl"], rec
    out = _no_hook_line(rec, capsys)
    assert "nothing was purged (deleted log.jsonl.attest.jsonl)" in out, out


def test_nothing_matched_keeps_the_old_wording_and_json(tmp_path, capsys):
    p = os.path.join(str(tmp_path), "log.jsonl")
    _write_oplog(p)
    rec = gov.erase(p, "no-such-text", hard=True)
    assert "cleaned" not in rec, rec
    assert "nothing was purged\n" in _no_hook_line(rec, capsys)


# ----------------------------- exit codes, as documented -----------------------------
def _exit_case(name, d):
    p = os.path.join(d, "log.jsonl")
    _write_oplog(p)
    if name == "nothing matched":
        return ["erase", p, "--match", "no-such-text", "--hard"], 0, ""
    if name == "refused: default attest chain present":
        assert _run("govern", ["attest", p], d).returncode == 0
        return ["erase", p, "--match", "walrus", "--hard"], 1, "--drop-attest"
    if name == "refused: bad op-log line":
        _bad_oplog(p)
        return ["erase", p, "--match", "walrus", "--hard"], 1, "repair --quarantine-bad-lines"
    if name == "invalid --match regex":
        return ["erase", p, "--match", "(", "--hard"], 1, "invalid --match"
    if name == "missing op-log":
        return ["erase", p + ".missing", "--match", "x"], 1, "not found"
    if name == "argument error: unknown option":
        return ["erase", p, "--match", "x", "--no-such-option"], 2, "unrecognized arguments"
    if name == "argument error: missing value":
        return ["erase", p, "--match"], 2, "expected one argument"
    raise AssertionError(name)


@pytest.mark.parametrize(
    "name",
    [
        "nothing matched",
        "refused: default attest chain present",
        "refused: bad op-log line",
        "invalid --match regex",
        "missing op-log",
        "argument error: unknown option",
        "argument error: missing value",
    ],
)
def test_exit_codes(name, tmp_path):
    argv, rc, says = _exit_case(name, str(tmp_path))
    res = _run("govern", argv, str(tmp_path))
    assert res.returncode == rc and says in res.stdout + res.stderr, (res.returncode, res.stderr)


def test_usage_text_documents_the_exit_codes_and_the_windows_key_mode():
    doc = " ".join((gov.__doc__ or "").split())
    assert "1 means a post-purge hook failed, or the command refused or could not run" in doc
    assert "Argument errors (an unknown option, a missing value) exit 2" in doc
    assert "not enforced on Windows" in doc
