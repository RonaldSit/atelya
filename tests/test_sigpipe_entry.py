"""SIGPIPE belongs to the command line, not to main().

amem_governance, amem_attest and amem_anchor are command lines: piped to `head` or `less` they end
quietly when the reader closes the pipe. That needs SIGPIPE at its default disposition, which is a
setting of the whole process, so only the entry point of the command line (cli(): the console
script and `python <file>.py`) makes it; main(argv) can be called from a longer-lived process (a
test runner, a server) and leaves the process's signal handling alone. Before, main() made the
setting, and a pytest process that had called it was later killed without output by a write to a
closed pipe (docs/evidence/sm-sigpipe/ in the atelya repository).

Run: pytest tests/test_sigpipe_entry.py -q   (the same file in atelya and atelya-public)
"""

import os
import re
import signal
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = ("amem_governance", "amem_attest", "amem_anchor")
pytestmark = pytest.mark.skipif(
    not hasattr(signal, "SIGPIPE"), reason="this platform has no SIGPIPE"
)

# Python starts with SIGPIPE ignored; the child says what the call left behind
CHILD = """import signal, sys
sys.path.insert(0, {root!r})
import {module} as m
signal.signal(signal.SIGPIPE, signal.SIG_IGN)
sys.argv = [{module!r}, "--help"]
try:
    {call}
except SystemExit as e:
    assert e.code == 0, e.code
sys.stderr.write(signal.Handlers(signal.getsignal(signal.SIGPIPE)).name)
"""


def _left_behind(module, call):
    r = subprocess.run(
        [sys.executable, "-c", CHILD.format(root=ROOT, module=module, call=call)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0 and "usage:" in r.stdout, r.stdout + r.stderr
    return r.stderr


@pytest.mark.parametrize("module", MODULES)
def test_main_leaves_the_sigpipe_disposition_of_its_process_alone(module):
    assert _left_behind(module, 'm.main(["--help"])') == "SIG_IGN"


@pytest.mark.parametrize("module", MODULES)
def test_the_command_line_entry_point_makes_sigpipe_end_the_process(module):
    assert _left_behind(module, "m.cli()") == "SIG_DFL"


@pytest.mark.parametrize("module", MODULES)
def test_run_as_a_script_it_ends_quietly_when_the_reader_closed_the_pipe(module):
    reader, writer = os.pipe()
    os.close(reader)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, module + ".py"), "--help"],
            stdout=writer,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    finally:
        os.close(writer)
    assert r.returncode == -signal.SIGPIPE and r.stderr == "", (r.returncode, r.stderr)


def test_the_console_scripts_of_these_modules_enter_through_cli():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
        text = f.read()
    package = re.search(r'^name\s*=\s*"([^"]+)"', text, re.M).group(1)
    scripts = re.findall(
        r'^[\w-]+\s*=\s*"(amem_(?:governance|attest|anchor)):(\w+)"\s*$', text, re.M
    )
    # atelya-attest ships the three command lines; atelya ships none of them (it depends on atelya-attest)
    assert sorted(m for m, _ in scripts) == (
        sorted(MODULES) if package == "atelya-attest" else []
    ), scripts
    assert all(function == "cli" for _, function in scripts), scripts
