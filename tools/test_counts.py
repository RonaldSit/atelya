"""Test-count manifest: run each suite, record its counts, compare them with the manifest.

CI test jobs run every suite through `run`, which writes one JSON file per suite. The last
step of each job runs `check`, and the `ci-summary` job runs `summary` over the counts every
job uploaded. The expected counts live in tests/expected_counts.json. A change to a suite's
count is made there, in the same commit as the change to the suite.

  python tools/test_counts.py run ID [--out DIR] -- CMD...
  python tools/test_counts.py check --job JOB [--variant V] [--results DIR] [--manifest M]
  python tools/test_counts.py summary --root DIR [--manifest M] [--needs-env NAME]
  python tools/test_counts.py workflow [--workflow W] [--manifest M] [--claude-md FILE --claude-md-job JOB]

`run` drops AMEM_TENANT_KEYS and AMEM_PRIVATE from the suite's environment. The same file is
in atelya-internal and atelya-public, byte-identical (tools/governance_sync_check.sh).
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys

MANIFEST = "tests/expected_counts.json"
RESULTS = "test-results"
DROP_ENV = ("AMEM_TENANT_KEYS", "AMEM_PRIVATE")
UPDATE_HINT = "if the change is intended, update tests/expected_counts.json in the same commit"

_CUSTOM = re.compile(r"=== (\d+) passed, (\d+) failed(?:, (\d+) skipped)? ===")
_E2E = re.compile(r"\[e2e\] (\d+) passed, (\d+) failed")
_FRACTION = re.compile(r"\b(\d+)/(\d+) PASS\b")
_TESTS_PASSED = re.compile(r"^(\d+) tests passed\.?$")
_PYTEST_LINE = re.compile(r"^=*\s*((?:\d+ [a-z]+(?:, )?)+) in [\d.]+s\b")
_PYTEST_PART = re.compile(r"(\d+) ([a-z]+)")


def parse_counts(text):
    """{"passed", "failed", "skipped"} from the last summary line of a suite's output, else None."""
    for line in reversed(text.splitlines()):
        line = line.strip()
        m = _CUSTOM.search(line)
        if m:
            return {"passed": int(m[1]), "failed": int(m[2]), "skipped": int(m[3] or 0)}
        m = _E2E.search(line)
        if m:
            return {"passed": int(m[1]), "failed": int(m[2]), "skipped": 0}
        m = _FRACTION.search(line)
        if m:
            return {"passed": int(m[1]), "failed": int(m[2]) - int(m[1]), "skipped": 0}
        m = _TESTS_PASSED.match(line)
        if m:
            return {"passed": int(m[1]), "failed": 0, "skipped": 0}
        m = _PYTEST_LINE.match(line)
        if m:
            got = {"passed": 0, "failed": 0, "skipped": 0}
            for n, word in _PYTEST_PART.findall(m[1]):
                if word == "passed":
                    got["passed"] += int(n)
                elif word in ("failed", "error", "errors", "xpassed"):
                    got["failed"] += int(n)
                elif word in ("skipped", "xfailed"):
                    got["skipped"] += int(n)
            return got
    return None


def cmd_run(a):
    if not a.cmd:
        sys.exit("run: give the suite's command after --")
    env = {k: v for k, v in os.environ.items() if k not in DROP_ENV}
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        a.cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = []
    for line in proc.stdout:
        sys.stdout.write(line)
        out.append(line)
    rc = proc.wait()
    counts = parse_counts("".join(out))
    record = {
        "id": a.id,
        "returncode": rc,
        "summary_found": counts is not None,
        "python": platform.python_version(),
        "platform": sys.platform,
    }
    record.update(counts or {"passed": 0, "failed": 0, "skipped": 0})
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, a.id + ".json"), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1)
    if counts is None:
        print(f"[counts] {a.id}: no summary line in its output, so it counts as zero checks")
        return rc or 1
    return rc


def load_manifest(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def expected_for(job, variant):
    exp = {k: dict(v) for k, v in job["suites"].items()}
    for sid, over in job.get("overrides", {}).get(variant, {}).items():
        exp.setdefault(sid, {}).update(over)
    return exp


def read_results(directory):
    got = {}
    if os.path.isdir(directory):
        for name in sorted(os.listdir(directory)):
            if name.endswith(".json"):
                with open(os.path.join(directory, name), encoding="utf-8") as f:
                    rec = json.load(f)
                got[rec.get("id", name[:-5])] = rec
    return got


def check_job(manifest, job_name, variant, directory):
    """Problems (strings) for one job's counts; empty when everything matches."""
    jobs = manifest["jobs"]
    if job_name not in jobs:
        return [f"job {job_name!r} is not in the manifest ({', '.join(sorted(jobs))})"]
    job = jobs[job_name]
    if variant not in job.get("variants", ["default"]):
        return [f"job {job_name}: variant {variant!r} is not in its variants {job.get('variants')}"]
    exp = expected_for(job, variant)
    got = read_results(directory)
    where = f"{job_name} ({variant})"
    problems = []
    for sid in exp:
        if sid not in got:
            problems.append(
                f"{where}: suite {sid} did not run (its step was removed, skipped, or never reached)"
            )
    for sid, rec in got.items():
        if sid not in exp:
            problems.append(f"{where}: suite {sid} ran but is not in the manifest: add it")
            continue
        total = rec["passed"] + rec["failed"] + rec["skipped"]
        if not rec.get("summary_found") or total == 0:
            problems.append(
                f"{where}: suite {sid} ran zero checks (no summary line, or all counts 0)"
            )
            continue
        if rec["failed"] or rec.get("returncode"):
            problems.append(
                f"{where}: suite {sid} failed ({rec['failed']} failed, exit {rec.get('returncode')})"
            )
        want_p, want_s = exp[sid].get("passed", 0), exp[sid].get("skipped", 0)
        if rec["passed"] != want_p or rec["skipped"] != want_s:
            problems.append(
                f"{where}: suite {sid} gave {rec['passed']} passed, {rec['skipped']} skipped; "
                f"the manifest expects {want_p} passed, {want_s} skipped ({UPDATE_HINT})"
            )
    return problems


def cmd_check(a):
    manifest = load_manifest(a.manifest)
    problems = check_job(manifest, a.job, a.variant, a.results)
    for p in problems:
        print("[counts] " + p)
    if problems:
        return 1
    n = len(expected_for(manifest["jobs"][a.job], a.variant))
    print(f"[counts] {a.job} ({a.variant}): {n} suites, every count as the manifest expects")
    return 0


def cmd_summary(a):
    manifest = load_manifest(a.manifest)
    problems = []
    expected_dirs = {}
    for job_name, job in manifest["jobs"].items():
        for variant in job.get("variants", ["default"]):
            expected_dirs[f"counts-{job_name}-{variant}"] = (job_name, variant)
    present = set(os.listdir(a.root)) if os.path.isdir(a.root) else set()
    for d, (job_name, variant) in sorted(expected_dirs.items()):
        if d not in present:
            problems.append(f"{job_name} ({variant}): uploaded no counts ({d} is missing)")
            continue
        problems += check_job(manifest, job_name, variant, os.path.join(a.root, d))
    for d in sorted(present - set(expected_dirs)):
        if d.startswith("counts-"):
            problems.append(f"{d}: counts from a job or variant the manifest does not list")
    if a.needs_env:
        needs = json.loads(os.environ.get(a.needs_env) or "{}")
        if not needs:
            problems.append(f"${a.needs_env} is empty: ci-summary needs every test job")
        for job_name, info in sorted(needs.items()):
            if info.get("result") != "success":
                problems.append(f"job {job_name} finished as {info.get('result')!r}, not success")
    for p in problems:
        print("[ci-summary] " + p)
    if problems:
        return 1
    print(f"[ci-summary] {len(expected_dirs)} job runs uploaded counts; every count as expected")
    return 0


def workflow_jobs(text):
    """{job id: its block of lines} for a GitHub Actions workflow (two-space job indent)."""
    jobs, current, in_jobs = {}, None, False
    for line in text.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            current = m[1]
            jobs[current] = []
        elif line and not line.startswith(" "):
            in_jobs = False
        elif current:
            jobs[current].append(line)
    return {k: "\n".join(v) for k, v in jobs.items()}


def claude_md_counts(text):
    """{suite id: passed} from the first ```bash block under "## Commands"."""
    block = text.split("## Commands", 1)[1].split("```bash", 1)[1].split("```", 1)[0]
    out = {}
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith("$PY") or "#" not in line:
            continue
        cmd, comment = line.split("#", 1)
        stems = [os.path.basename(t)[:-3] for t in cmd.split() if t.endswith(".py")]
        m = re.search(r"(\d+)/\d+ PASS|(\d+) tests passed|(\d+) passed", comment)
        if stems and m:
            out["+".join(stems)] = int(next(g for g in m.groups() if g))
    return out


def cmd_workflow(a):
    manifest = load_manifest(a.manifest)
    with open(a.workflow, encoding="utf-8") as f:
        jobs = workflow_jobs(f.read())
    problems = []
    for job_name, job in manifest["jobs"].items():
        block = jobs.get(job_name)
        if block is None:
            problems.append(f"manifest job {job_name} is not a job of {a.workflow}")
            continue
        ran = re.findall(r"test_counts\.py\"? run (\S+)", block)
        dupes = sorted({s for s in ran if ran.count(s) > 1})
        if dupes:
            problems.append(f"{job_name}: suites run twice: {', '.join(dupes)}")
        for sid in sorted(set(job["suites"]) - set(ran)):
            problems.append(
                f"{job_name}: manifest suite {sid} has no `test_counts.py run {sid}` step"
            )
        for sid in sorted(set(ran) - set(job["suites"])):
            problems.append(f"{job_name}: step runs {sid}, which the manifest does not list")
        if f"check --job {job_name}" not in block:
            problems.append(f"{job_name}: no `test_counts.py check --job {job_name}` step")
        if "name: counts-${{ github.job }}-" not in block:
            problems.append(f"{job_name}: no upload of counts-${{{{ github.job }}}}-<variant>")
    summary = jobs.get("ci-summary")
    if summary is None:
        problems.append("no ci-summary job")
    else:
        m = re.search(r"needs:\s*\[([^\]]*)\]", summary)
        needed = {s.strip() for s in m[1].split(",")} if m else set()
        for job_name in sorted(set(jobs) - {"ci-summary"} - needed):
            problems.append(f"ci-summary does not need job {job_name}")
    if a.claude_md:
        with open(a.claude_md, encoding="utf-8") as f:
            listed = claude_md_counts(f.read())
        suites = manifest["jobs"][a.claude_md_job]["suites"]
        for sid in sorted(set(suites) | set(listed)):
            if sid not in listed:
                problems.append(
                    f"{a.claude_md}: manifest suite {sid} is missing from the Commands block"
                )
            elif sid not in suites:
                problems.append(
                    f"{a.claude_md}: {sid} is in the Commands block, not in the manifest"
                )
            elif listed[sid] != suites[sid].get("passed"):
                problems.append(
                    f"{a.claude_md}: {sid} says {listed[sid]} passed, "
                    f"the manifest {suites[sid].get('passed')}"
                )
    for p in problems:
        print("[workflow] " + p)
    if problems:
        return 1
    print(f"[workflow] {a.workflow} and {a.manifest} agree")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    suite_cmd = []
    if "--" in argv:  # run: everything after -- is the suite's own command line
        i = argv.index("--")
        argv, suite_cmd = argv[:i], argv[i + 1 :]
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("mode", choices=["run", "check", "summary", "workflow"])
    ap.add_argument("id", nargs="?", help="run: the suite id")
    ap.add_argument("--out", default=RESULTS, help="run: where the counts go")
    ap.add_argument("--job", help="check: the job")
    ap.add_argument("--variant", default="default", help="check: the matrix entry")
    ap.add_argument("--results", default=RESULTS, help="check: the job's counts")
    ap.add_argument("--root", help="summary: one counts-<job>-<variant> folder per job run")
    ap.add_argument("--needs-env", help="summary: env var holding toJSON(needs)")
    ap.add_argument("--manifest", default=MANIFEST)
    ap.add_argument("--workflow", default=".github/workflows/tests.yml")
    ap.add_argument("--claude-md", help="workflow: also compare this file's Commands block")
    ap.add_argument("--claude-md-job", default="offline-suites")
    a = ap.parse_intermixed_args(argv)
    if a.mode == "run" and not a.id:
        ap.error("run needs the suite id")
    if a.mode == "check" and not a.job:
        ap.error("check needs --job")
    if a.mode == "summary" and not a.root:
        ap.error("summary needs --root")
    a.cmd = suite_cmd
    modes = {"run": cmd_run, "check": cmd_check, "summary": cmd_summary, "workflow": cmd_workflow}
    return modes[a.mode](a)


if __name__ == "__main__":
    sys.exit(main())
