"""tools/test_counts.py: the test-count manifest (harness plan H1).

Same file in atelya-internal and atelya-public. Fixtures for every problem the checker must
report: a missing suite, a suite not in the manifest, zero checks, a failure, a count that
dropped, a job that uploaded no counts, a job that did not succeed, and a workflow or
CLAUDE.md out of step with the manifest. The last test checks this repo's own workflow.
"""

import importlib.util
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "test_counts.py")


def _tool():
    if not os.path.exists(TOOL):
        return None
    spec = importlib.util.spec_from_file_location("test_counts_tool", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


T = _tool()


def need(name):
    assert T is not None, f"{TOOL} does not exist"
    assert hasattr(T, name), f"tools/test_counts.py has no {name}"
    return getattr(T, name)


MANIFEST = {
    "jobs": {
        "suites": {
            "variants": ["3.10", "3.12"],
            "suites": {"alpha": {"passed": 3}, "beta": {"passed": 2, "skipped": 1}},
            "overrides": {"3.10": {"beta": {"passed": 3, "skipped": 0}}},
        },
        "single": {"suites": {"gamma": {"passed": 1}}},
    }
}


def write_results(d, recs):
    os.makedirs(d, exist_ok=True)
    for sid, (p, f, s) in recs.items():
        rec = {"id": sid, "passed": p, "failed": f, "skipped": s, "returncode": 1 if f else 0}
        rec["summary_found"] = True
        with open(os.path.join(d, sid + ".json"), "w", encoding="utf-8") as fh:
            json.dump(rec, fh)


def run_cli(*args, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(
        [sys.executable, TOOL, *args], capture_output=True, text=True, env=e, timeout=120
    )


# ---------------------------------------------------------------- parse_counts
def test_parse_counts_every_summary_format():
    parse = need("parse_counts")
    cases = {
        "x\n=== 14 passed, 0 failed ===\n": (14, 0, 0),
        "=== 58 passed, 0 failed, 2 skipped ===": (58, 0, 2),
        "[e2e] 10 passed, 0 failed": (10, 0, 0),
        "P0-5 ... INTEGRATION 23/23 PASS": (23, 0, 0),
        "INTEGRATION 3/5 PASS": (3, 2, 0),
        "\n41 tests passed.": (41, 0, 0),
        "....\n407 passed in 23.76s": (407, 0, 0),
        "1 failed, 406 passed, 2 skipped in 1.02s": (406, 1, 2),
        "========= 3 passed, 1 error in 0.20s =========": (3, 1, 0),
    }
    for text, (p, f, s) in cases.items():
        assert parse(text) == {"passed": p, "failed": f, "skipped": s}, text


def test_parse_counts_takes_the_last_summary_and_none_without_one():
    parse = need("parse_counts")
    assert parse("=== 1 passed, 0 failed ===\nmore\n=== 5 passed, 1 failed ===") == {
        "passed": 5,
        "failed": 1,
        "skipped": 0,
    }
    assert parse("Traceback (most recent call last):\n  boom") is None


# ---------------------------------------------------------------- run
def test_run_writes_the_counts_and_drops_the_tenant_keys(tmp_path):
    need("cmd_run")
    suite = tmp_path / "suite.py"
    suite.write_text(
        "import os\n"
        "print('keys' if 'AMEM_TENANT_KEYS' in os.environ else 'no-keys')\n"
        "print('private' if 'AMEM_PRIVATE' in os.environ else 'not-private')\n"
        "print('=== 4 passed, 0 failed, 1 skipped ===')\n"
    )
    out = tmp_path / "res"
    env = {"AMEM_TENANT_KEYS": "/nowhere.json", "AMEM_PRIVATE": "1"}
    r = run_cli("run", "s1", "--out", str(out), "--", sys.executable, str(suite), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "no-keys" in r.stdout and "not-private" in r.stdout
    rec = json.loads((out / "s1.json").read_text())
    assert (rec["passed"], rec["failed"], rec["skipped"], rec["summary_found"]) == (4, 0, 1, True)


def test_run_without_a_summary_fails_and_records_zero(tmp_path):
    need("cmd_run")
    suite = tmp_path / "quiet.py"
    suite.write_text("print('nothing to see')\n")
    out = tmp_path / "res"
    r = run_cli("run", "q", "--out", str(out), "--", sys.executable, str(suite))
    assert r.returncode == 1, r.stdout
    rec = json.loads((out / "q.json").read_text())
    assert rec["summary_found"] is False and rec["passed"] == 0


def test_run_keeps_the_suite_exit_code(tmp_path):
    need("cmd_run")
    suite = tmp_path / "bad.py"
    suite.write_text("print('=== 1 passed, 1 failed ===')\nraise SystemExit(3)\n")
    r = run_cli("run", "b", "--out", str(tmp_path / "r"), "--", sys.executable, str(suite))
    assert r.returncode == 3


# ---------------------------------------------------------------- check
def test_check_passes_when_every_count_matches(tmp_path):
    check = need("check_job")
    write_results(tmp_path, {"alpha": (3, 0, 0), "beta": (2, 0, 1)})
    assert check(MANIFEST, "suites", "3.12", str(tmp_path)) == []


def test_check_reports_a_suite_that_did_not_run(tmp_path):
    check = need("check_job")
    write_results(tmp_path, {"alpha": (3, 0, 0)})
    probs = check(MANIFEST, "suites", "3.12", str(tmp_path))
    assert len(probs) == 1 and "suite beta did not run" in probs[0], probs


def test_check_reports_a_suite_missing_from_the_manifest(tmp_path):
    check = need("check_job")
    write_results(tmp_path, {"alpha": (3, 0, 0), "beta": (2, 0, 1), "delta": (1, 0, 0)})
    probs = check(MANIFEST, "suites", "3.12", str(tmp_path))
    assert len(probs) == 1 and "delta ran but is not in the manifest" in probs[0], probs


def test_check_reports_a_deleted_test(tmp_path):
    check = need("check_job")
    write_results(tmp_path, {"alpha": (2, 0, 0), "beta": (2, 0, 1)})
    probs = check(MANIFEST, "suites", "3.12", str(tmp_path))
    assert len(probs) == 1 and "alpha gave 2 passed" in probs[0], probs
    assert "expected_counts.json in the same commit" in probs[0]


def test_check_reports_a_changed_skip_count(tmp_path):
    check = need("check_job")
    write_results(tmp_path, {"alpha": (3, 0, 0), "beta": (2, 0, 0)})
    probs = check(MANIFEST, "suites", "3.12", str(tmp_path))
    assert len(probs) == 1 and "beta gave 2 passed, 0 skipped" in probs[0], probs


def test_check_reports_zero_checks_and_failures(tmp_path):
    check = need("check_job")
    write_results(tmp_path, {"alpha": (0, 0, 0), "beta": (1, 1, 1)})
    probs = check(MANIFEST, "suites", "3.12", str(tmp_path))
    assert any("alpha ran zero checks" in p for p in probs), probs
    assert any("beta failed" in p for p in probs), probs


def test_check_applies_the_variant_override(tmp_path):
    check = need("check_job")
    write_results(tmp_path, {"alpha": (3, 0, 0), "beta": (3, 0, 0)})
    assert check(MANIFEST, "suites", "3.10", str(tmp_path)) == []
    assert check(MANIFEST, "suites", "3.12", str(tmp_path)) != []


def test_check_refuses_an_unknown_job_or_variant(tmp_path):
    check = need("check_job")
    assert "not in the manifest" in check(MANIFEST, "nope", "default", str(tmp_path))[0]
    assert "variant '3.9'" in check(MANIFEST, "suites", "3.9", str(tmp_path))[0]


def test_check_cli_exit_codes(tmp_path):
    need("cmd_check")
    m = tmp_path / "m.json"
    m.write_text(json.dumps(MANIFEST))
    write_results(tmp_path / "ok", {"gamma": (1, 0, 0)})
    r = run_cli("check", "--job", "single", "--results", str(tmp_path / "ok"), "--manifest", str(m))
    assert r.returncode == 0, r.stdout
    r = run_cli(
        "check", "--job", "single", "--results", str(tmp_path / "none"), "--manifest", str(m)
    )
    assert r.returncode == 1 and "gamma did not run" in r.stdout


# ---------------------------------------------------------------- summary
def _all_counts(root):
    write_results(root / "counts-suites-3.10", {"alpha": (3, 0, 0), "beta": (3, 0, 0)})
    write_results(root / "counts-suites-3.12", {"alpha": (3, 0, 0), "beta": (2, 0, 1)})
    write_results(root / "counts-single-default", {"gamma": (1, 0, 0)})


def _summary(tmp_path, needs):
    m = tmp_path / "m.json"
    m.write_text(json.dumps(MANIFEST))
    return run_cli(
        "summary",
        "--root",
        str(tmp_path / "root"),
        "--manifest",
        str(m),
        "--needs-env",
        "NEEDS",
        env={"NEEDS": json.dumps(needs)},
    )


OK_NEEDS = {"suites": {"result": "success"}, "single": {"result": "success"}}


def test_summary_passes_when_every_job_uploaded_matching_counts(tmp_path):
    need("cmd_summary")
    _all_counts(tmp_path / "root")
    r = _summary(tmp_path, OK_NEEDS)
    assert r.returncode == 0, r.stdout


def test_summary_reports_a_matrix_entry_that_uploaded_nothing(tmp_path):
    need("cmd_summary")
    _all_counts(tmp_path / "root")
    for f in (tmp_path / "root" / "counts-suites-3.10").iterdir():
        f.unlink()
    (tmp_path / "root" / "counts-suites-3.10").rmdir()
    r = _summary(tmp_path, OK_NEEDS)
    assert r.returncode == 1 and "suites (3.10): uploaded no counts" in r.stdout, r.stdout


def test_summary_reports_a_job_that_did_not_succeed(tmp_path):
    need("cmd_summary")
    _all_counts(tmp_path / "root")
    r = _summary(tmp_path, {**OK_NEEDS, "lint": {"result": "skipped"}})
    assert r.returncode == 1 and "job lint finished as 'skipped'" in r.stdout, r.stdout


def test_summary_reports_empty_needs_and_unknown_artifacts(tmp_path):
    need("cmd_summary")
    _all_counts(tmp_path / "root")
    write_results(tmp_path / "root" / "counts-ghost-default", {"x": (1, 0, 0)})
    r = _summary(tmp_path, {})
    assert r.returncode == 1
    assert "empty" in r.stdout and "counts-ghost-default" in r.stdout, r.stdout


# ---------------------------------------------------------------- workflow
WORKFLOW = """name: tests
on: push
jobs:
  suites:
    steps:
      - run: python tools/test_counts.py run alpha -- python tests/a.py
      - run: python tools/test_counts.py run beta -- python -m pytest tests/b.py -q
      - run: python tools/test_counts.py check --job suites --variant x
      - uses: actions/upload-artifact@v4
        with:
          name: counts-${{ github.job }}-${{ matrix.python || 'default' }}
  single:
    steps:
      - run: python "$W/tools/test_counts.py" run gamma -- python tests/g.py
      - run: python tools/test_counts.py check --job single
      - uses: actions/upload-artifact@v4
        with:
          name: counts-${{ github.job }}-${{ matrix.python || 'default' }}
  lint:
    steps:
      - run: ruff check .
  ci-summary:
    needs: [suites, single, lint]
    steps:
      - run: python tools/test_counts.py summary --root all
"""

CLAUDE_MD = """# x
## Commands
```bash
PY=python
$PY tests/alpha.py          # 3 passed, 0 failed
$PY -m pytest tests/beta.py -q   # 2 passed
```
"""


def _workflow(tmp_path, workflow=WORKFLOW, claude=None, job="suites"):
    (tmp_path / "w.yml").write_text(workflow)
    m = tmp_path / "m.json"
    m.write_text(json.dumps(MANIFEST))
    args = ["workflow", "--workflow", str(tmp_path / "w.yml"), "--manifest", str(m)]
    if claude is not None:
        (tmp_path / "C.md").write_text(claude)
        args += ["--claude-md", str(tmp_path / "C.md"), "--claude-md-job", job]
    return run_cli(*args)


def test_workflow_passes_when_steps_and_manifest_agree(tmp_path):
    need("cmd_workflow")
    r = _workflow(tmp_path, claude=CLAUDE_MD)
    assert r.returncode == 0, r.stdout


def test_workflow_reports_a_removed_step(tmp_path):
    need("cmd_workflow")
    wf = WORKFLOW.replace(
        "      - run: python tools/test_counts.py run alpha -- python tests/a.py\n", ""
    )
    r = _workflow(tmp_path, wf)
    assert r.returncode == 1 and "manifest suite alpha has no" in r.stdout, r.stdout


def test_workflow_reports_an_unlisted_step_and_a_duplicate(tmp_path):
    need("cmd_workflow")
    wf = WORKFLOW.replace(
        "      - run: python tools/test_counts.py check --job suites",
        "      - run: python tools/test_counts.py run omega -- x\n"
        "      - run: python tools/test_counts.py run alpha -- x\n"
        "      - run: python tools/test_counts.py check --job suites",
    )
    r = _workflow(tmp_path, wf)
    assert "runs omega, which the manifest does not list" in r.stdout, r.stdout
    assert "suites run twice: alpha" in r.stdout, r.stdout


def test_workflow_reports_a_missing_check_upload_or_need(tmp_path):
    need("cmd_workflow")
    wf = (
        WORKFLOW.replace("check --job single", "check --job other")
        .replace("needs: [suites, single, lint]", "needs: [suites, single]")
        .replace(
            "          name: counts-${{ github.job }}-${{ matrix.python || 'default' }}\n  single:",
            "          name: other\n  single:",
        )
    )
    r = _workflow(tmp_path, wf)
    assert "single: no `test_counts.py check --job single`" in r.stdout, r.stdout
    assert "suites: no upload of counts-" in r.stdout, r.stdout
    assert "ci-summary does not need job lint" in r.stdout, r.stdout


def test_workflow_reports_a_manifest_job_the_workflow_lacks(tmp_path):
    need("cmd_workflow")
    wf = WORKFLOW.replace("  single:\n", "  renamed:\n").replace(
        "needs: [suites, single, lint]", "needs: [suites, renamed, lint]"
    )
    r = _workflow(tmp_path, wf)
    assert r.returncode == 1 and "manifest job single is not a job of" in r.stdout, r.stdout


def test_workflow_reports_claude_md_out_of_step(tmp_path):
    need("cmd_workflow")
    claude = CLAUDE_MD.replace("# 3 passed", "# 4 passed").replace(
        "$PY -m pytest tests/beta.py -q   # 2 passed\n", "$PY tests/z.py  # 1 passed, 0 failed\n"
    )
    r = _workflow(tmp_path, claude=claude)
    assert "alpha says 4 passed, the manifest 3" in r.stdout, r.stdout
    assert "manifest suite beta is missing" in r.stdout, r.stdout
    assert "z is in the Commands block, not in the manifest" in r.stdout, r.stdout


# ---------------------------------------------------------------- this repo
def test_this_repo_workflow_and_manifest_agree():
    need("cmd_workflow")
    args = ["workflow", "--workflow", os.path.join(ROOT, ".github", "workflows", "tests.yml")]
    args += ["--manifest", os.path.join(ROOT, "tests", "expected_counts.json")]
    if os.path.exists(os.path.join(ROOT, "CLAUDE.md")):
        args += ["--claude-md", os.path.join(ROOT, "CLAUDE.md")]
    r = run_cli(*args)
    assert r.returncode == 0, r.stdout + r.stderr
