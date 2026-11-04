"""The atelya-govern command line on every supported Python.

1. Every documented command form runs and does its job. The forms are
   extracted, not copied: from the docs of this repo that exist among DOCS,
   the usage block of amem_governance.py, and the repair command printed by
   the op-log load error (amem_governance, and amem.oplog where the package is
   in the repo). Optional [parts] are expanded. Each form runs as a subprocess
   on temp files.
2. Options between the subcommand and the path work too (a few undocumented
   orders).
3. A hard purge without post-purge hooks names every file it cleaned.
4. The exit codes are the ones the usage text documents.

With parser.parse_args, argparse on Python 3.10, 3.11, 3.12.0-3.12.6 and
3.13.0 matched the optional op-log positional to zero strings before an option
and then rejected the path as "unrecognized arguments" (exit 2), so
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
import amem_governance as gov  # noqa: E402

GOV = str(REPO / "amem_governance.py")
DOCS = [
    "README.md",
    "ATTESTATION.md",
    "docs/PRIVATE-QUICKSTART.md",
    "ATELYA-COMPLIANCE-ONEPAGER-EN.md",
]
PROGRAM = re.compile(r"(?:atelya-govern|amem_governance\.py)(?=[\s`]|$)")
CMDS = {
    "audit",
    "lineage",
    "conflicts",
    "erase",
    "retention",
    "summary",
    "attest",
    "verify-chain",
    "repair",
}
VALUE_OPTS = {"--id", "--match", "--out", "--max-age-days", "--max-active", "--key", "--keyfile"}
FLAG_OPTS = {"--hard", "--selftest", "--quarantine-bad-lines", "--apply", "--drop-attest"}
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


def _shape(cmdline):
    """A tuple like ("repair", "--quarantine-bad-lines", "P"): positionals become
    "P", value options become (option, None), except --out, which keeps its file
    suffix. None when the text is not a command (prose that names the tool)."""
    try:
        toks = shlex.split(cmdline)
    except ValueError:
        return None
    if not toks or not (toks[0] in CMDS or toks[0].startswith("--")):
        return None
    shape, k = [], 0
    while k < len(toks):
        tok = toks[k]
        if k == 0 and tok in CMDS:
            shape.append(tok)
        elif tok.startswith("--"):
            opt, eq, val = tok.partition("=")
            if opt in VALUE_OPTS:
                if not eq:
                    k += 1
                    val = toks[k] if k < len(toks) else ""
                shape.append((opt, Path(val).suffix or ".out") if opt == "--out" else (opt, None))
            elif opt in FLAG_OPTS:
                shape.append(opt)
            else:
                raise AssertionError(
                    f"unknown option {tok!r} in a documented form: update this test"
                )
        else:
            shape.append("P")
        k += 1
    return tuple(shape)


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


def documented_forms():
    """{shape: [sources]} for every documented atelya-govern command form."""
    forms = {}

    def add(source, text):
        for variant in _expand(text):
            s = _shape(variant)
            if s and (s[0] not in CMDS or "P" in s):  # "atelya-govern attest" alone is a mention
                forms.setdefault(s, []).append(source)

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
            for m in PROGRAM.finditer(line):
                add(f"{rel}:{n}", _cut(line[m.end() :]))
    for n, line in enumerate((gov.__doc__ or "").splitlines(), 1):
        m = re.match(r"\s*python3? amem_governance\.py (.*)$", line)
        if m:
            add(f"usage line {n}", m.group(1))
    for source, msg in _load_error_messages():
        m = re.search(r"atelya-govern (.*?) \(then add (--[\w-]+)", msg)
        assert m, f"{source} names no repair command: {msg}"
        add(source, m.group(1))
        add(f"{source} (+{m.group(2)})", f"{m.group(1)} {m.group(2)}")
    return forms


FORMS = documented_forms()
INTERLEAVED = [
    ("erase", "--hard", "P", ("--match", None)),
    ("erase", ("--match", None), "P"),
    ("retention", ("--max-active", None), "P", "--hard"),
    ("attest", ("--out", ".jsonl"), "P"),
    ("audit", ("--out", ".csv"), "P"),
    ("lineage", ("--id", None), "P"),
    ("repair", "--apply", "--quarantine-bad-lines", "P"),
]


def _label(shape):
    return " ".join(x if isinstance(x, str) else f"{x[0]} {x[1] or 'V'}" for x in shape)


# ----------------------------- running a form -----------------------------
def _write_oplog(path):
    Path(path).write_text("".join(json.dumps(r) + "\n" for r in RECORDS), encoding="utf-8")


def _env():
    env = dict(os.environ)
    env.pop("AMEM_ATTEST_KEY", None)
    env["PYTHONUTF8"] = "1"
    return env


def _run(argv, cwd):
    return subprocess.run(
        [sys.executable, GOV, *argv],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        env=_env(),
    )


def _concrete(shape, d):
    """argv for a shape, on fresh files in d, and what the run must show."""
    cmd = shape[0] if shape[0] in CMDS else None
    oplog = os.path.join(d, "log.jsonl")
    (_bad_oplog if cmd == "repair" else _write_oplog)(oplog)
    keyfile = os.path.join(d, "attest.key")
    Path(keyfile).write_text(KEY, encoding="utf-8")
    key_args = []
    for item in shape:
        if isinstance(item, tuple) and item[0] == "--key":
            key_args = ["--key", KEY]
        if isinstance(item, tuple) and item[0] == "--keyfile":
            key_args = ["--keyfile", keyfile]
    chain = os.path.join(d, "prebuilt.chain.jsonl")
    if cmd == "verify-chain":
        built = _run(["attest", oplog, "--out", chain, *key_args], d)
        assert built.returncode == 0, built.stderr
    argv, out_file = [], None
    for item in shape:
        if item == "P":
            argv.append(chain if cmd == "verify-chain" else oplog)
        elif isinstance(item, tuple):
            opt, val = item
            if opt == "--out":
                out_file = os.path.join(d, "out" + val)
                argv += [opt, out_file]
            elif opt == "--key":
                argv += [opt, KEY]
            elif opt == "--keyfile":
                argv += [opt, keyfile]
            else:
                argv += [
                    opt,
                    {
                        "--id": "r1",
                        "--match": "walrus",
                        "--max-age-days": "36500",
                        "--max-active": "10",
                    }[opt],
                ]
        else:
            argv.append(item)
    return argv, {"cmd": cmd, "oplog": oplog, "out": out_file, "apply": "--apply" in shape}


def _check_did_its_job(res, ctx):
    cmd, out = ctx["cmd"], res.stdout
    first = out.splitlines()[0] if out.strip() else ""
    if cmd == "erase":
        assert json.loads(first)["matched"] == 1, out
    elif cmd == "retention":
        assert "retired" in json.loads(first), out
    elif cmd == "attest":
        assert os.path.getsize(ctx["out"] or ctx["oplog"] + ".attest.jsonl") > 0
    elif cmd == "verify-chain":
        assert "VERIFIED" in out, out
    elif cmd == "repair":
        assert "line 2: invalid_json" in out, out
        if ctx["apply"]:
            assert "not json" not in Path(ctx["oplog"]).read_text(encoding="utf-8")
            assert os.path.exists(ctx["oplog"] + ".corrupt")
    elif cmd == "audit":
        assert os.path.getsize(ctx["out"]) > 0 if ctx["out"] else out.strip(), out
    elif cmd == "lineage":
        assert "r1" in out, out
    elif cmd is None:  # --selftest
        assert "PASS" in out or "pass" in out.lower(), out


def _run_form(shape, tmp_path):
    argv, ctx = _concrete(shape, str(tmp_path))
    res = _run(argv, str(tmp_path))
    msg = (
        f"argv {argv}\nrc {res.returncode}\nstdout {res.stdout[-600:]}\nstderr {res.stderr[-600:]}"
    )
    assert "unrecognized arguments" not in res.stderr, msg
    assert res.returncode == 0, msg
    _check_did_its_job(res, ctx)


@pytest.mark.parametrize(
    "shape",
    [pytest.param(s, id=f"{_label(s)} [{src[0]}]") for s, src in sorted(FORMS.items(), key=str)],
)
def test_documented_form_runs(shape, tmp_path):
    _run_form(shape, tmp_path)


@pytest.mark.parametrize("shape", [pytest.param(s, id=_label(s)) for s in INTERLEAVED])
def test_option_before_the_path_runs(shape, tmp_path):
    _run_form(shape, tmp_path)


def test_extraction_finds_the_forms_users_are_told_to_run():
    repair = ("repair", "--quarantine-bad-lines", "P")
    assert repair in FORMS and repair + ("--apply",) in FORMS
    assert any(s.startswith("amem_governance load error") for s in FORMS[repair])
    assert any(s.startswith("usage line") for s in FORMS[repair])
    assert ("--selftest",) in FORMS
    assert len(FORMS) >= 20, sorted(FORMS, key=str)


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
    assert _run(["attest", p], str(tmp_path)).returncode == 0
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
    assert _run(["attest", p], str(tmp_path)).returncode == 0
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
        assert _run(["attest", p], d).returncode == 0
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
    res = _run(argv, str(tmp_path))
    assert res.returncode == rc and says in res.stdout + res.stderr, (res.returncode, res.stderr)


def test_usage_text_documents_the_exit_codes_and_the_windows_key_mode():
    doc = " ".join((gov.__doc__ or "").split())
    assert "1 means a post-purge hook failed, or the command refused or could not run" in doc
    assert "Argument errors (an unknown option, a missing value) exit 2" in doc
    assert "not enforced on Windows" in doc
