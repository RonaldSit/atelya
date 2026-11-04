# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The changes below fix residue that a hard `erase` or hard `retention` left
behind. Before, a hard purge removed the record's own lines but could leave
its text, or values derived from it, elsewhere in the op-log: old
`key_conflict` events (an 80-character excerpt and no id), `flag` events
naming the record (kept by retention), old-format lines without an id
(matched but not removed), purge markers holding a plain SHA-256 of the
pattern, and `.vec` lines of ids the op-log no longer names. The details are
under Changed below. The attest hash chain has limits. It stores every
op-log event verbatim, so it holds the text of every record it covers. A
hard purge therefore refuses while `<oplog>.attest.jsonl` exists, and
`--drop-attest` deletes that file together with the history it recorded. A
chain written elsewhere with `--out` is neither checked nor cleaned. A chain
that stores only hashes and can be verified across purged positions is not
implemented. The tool rewrites only the op-log and its side files (`.torn`,
`.corrupt`, `.vec`); copies kept anywhere else are reached only by installed
post-purge hooks, or not at all.

### Changed
- **Hard purge removes every trace it can reach, by one rule for erase and
  retention.** Every event naming a purged id in `id`, `a`, `b` or `holder`
  goes (retention used to keep flags); old `key_conflict` events, which stored
  the first 80 characters of a text and no id, go when that excerpt is a
  prefix of a purged text; old-format `{"text": ...}` lines without an id are
  purgeable (they were matched but left in the file); `<oplog>.torn` and
  `<oplog>.corrupt` lines holding a purged text (a prefix of the `"text"`
  value, or a 20-character window, matched raw and JSON-escaped) go; and
  `.vec` lines of ids the op-log no longer names go.
- **Purge markers hold HMAC-SHA256 of the pattern** (`erasure:hmac-sha256:`)
  with `<data_dir>/.erasure_key` (32 bytes, mode 0600, created on first need,
  never deleted by erase or retention; back it up with the data directory,
  or existing HMACs can no longer be checked). A plain SHA-256 of a short or
  guessable pattern could be confirmed by hashing guesses. Existing
  `erasure:sha256:` markers are left as written. A marker for an id-less line
  names no id (its positional id would point at another line after the
  rewrite). On Windows the 0600 mode is not enforced (Windows keeps only the
  read-only bit of a POSIX mode): the key file relies on the ACL of the
  location that holds the data directory.
- **A hard purge refuses while `<oplog>.attest.jsonl` exists**, because the
  chain stores every event verbatim; `--drop-attest` deletes the chain file
  and proceeds. Chain files written elsewhere with `--out` are not checked.
  8 new tests, 2 changed (they pinned the plain-sha256 marker and retention
  keeping flags); suite: **93**.
- **Bad op-log lines are no longer skipped silently.** The op-log is the
  source of truth, so `read_log` (and every command built on it) now raises
  `OplogError` for a line that is not valid JSON or is JSON but not an
  object, naming the file and line number and the repair command; the
  message never contains the line. Before, invalid JSON was skipped and a
  non-object line crashed with `AttributeError` or `TypeError`.
  - A **torn tail** (the last line has no newline and does not parse, as
    left by a crash mid-write) is appended unchanged to `<oplog>.torn` and
    truncated, and the read continues.
  - Hard `erase` and `retention` keep every other line **byte for byte**
    (blank lines and legacy `{"text": ...}` lines included); before, they
    re-serialized every kept event and dropped invalid lines. They refuse
    to run when a middle line is bad.
  - `verify-chain` never repairs the chain file; a bad line there is
    reported as tampering.
  - Every append, rewrite, torn-tail move and repair holds `<oplog>.lock`
    (`fcntl.flock`; `msvcrt.locking` on Windows, not tested on Windows).

### Added
- `repair --quarantine-bad-lines <oplog>`: a dry run lists bad lines by
  number and category, never their content; `--apply` moves them unchanged
  to `<oplog>.corrupt` as `<line number><TAB><line>`, moves a torn tail to
  `<oplog>.torn`, and keeps every other line in order. 11 new tests, one
  replaced (it pinned the silent skipping); suite: **85**.
- Post-purge hooks. After every **hard** erase or retention, each installed entry
  point in the group `atelya.purge_hooks` is called as
  `hook(oplog_path, purged, match)`: `purged` maps each purged record id to the
  SHA-256 digests of every text it ever had; `match` is the erase regex (`None`
  for retention). Hooks **never receive the erased text**. They let a product
  that keeps copies of memory text outside the op-log (session caches, tool
  files) remove them in the same command. The CLI prints every hook and its
  outcome, or one line saying none is installed; a failed hook makes it exit 1
  with `ERASE INCOMPLETE`. A hard erase that matches nothing still runs the
  hooks, so re-running the same command finishes an interrupted cleanup.
  Soft mode runs no hooks (the text stays in the op-log by design). Without
  hooks installed, behaviour is unchanged. 7 new tests; suite: **70**.

### Fixed
- `erase` that matches no record printed `HARD PURGE (content removed)` (or
  `SOFT forget` without `--hard`), and with no hooks installed also claimed
  "the op-log and its .vec sidecar were purged". Nothing had been touched.
  It now prints `NO MATCH: no record matched --match; the op-log was not
  changed` and "nothing was purged"; the pattern is never echoed, since it
  may be the very text being erased. `retention` with nothing due prints
  "nothing was purged" too. Output for a matching erase and exit codes are
  unchanged. 5 new tests; suite: **75**.

### Changed
- Readability refactor: cryptic locals renamed (`ev`→`event`, `cp`→`checkpoint`,
  `ch`→`chain_head`, `r`→`record`, `rx`→`regex`, `st`→`status`, `ap`→`parser`),
  the dead `OPS_WRITE` constant removed, and one implicit `return None` made an
  explicit `return 0`. No behaviour change — selftests, the 63-test suite and the
  hard-erase marker digest are identical before and after. Not yet on PyPI.

## [0.1.1] — 2026-07-16

### Added
- `tests/test_amem_governance.py`: 22-case suite covering replay/supersede,
  GDPR **soft-forget vs hard-purge** (purge itself logged; the marker's
  `reason` records a **SHA-256 digest** of the erasure pattern — verifiable
  without ever leaking it), retention by age and by active-cap
  (oldest-first), audit timeline/export, lineage, conflict winners, CLI guard
  exits, and an attest → verify-chain → tamper round-trip. Total suite: **63**.
- `SECURITY.md` (private vulnerability reporting) and this `CHANGELOG.md`.
- CI: `ruff format --check` + `ruff check` lint job alongside the
  Python 3.10–3.13 test matrix.

### Changed
- CLI internals: argparse result variable `A` → `args` (PEP 8); op-log parse
  `except Exception` narrowed to `ValueError`; JSON export uses a context
  manager; `SIGPIPE` restored to default so piping to `head`/`less` exits
  quietly (141) instead of tracebacking.
- Code style: `ruff format` applied repo-wide (line length 100); combined
  imports split (E401). No behavior change — full suite green before/after.
- Packaging: SPDX `license = "Apache-2.0"` string (deprecated classifier
  removed); version bumped to 0.1.1.
- Docs: the 60-second demo's tamper step is now cross-platform (the previous
  `sed -i` form breaks on macOS/BSD sed).

### Fixed
- `atelya-anchor check` no longer silently passes when `--label` is forgotten
  but the ledger holds anchors under other labels — it lists them and fails
  (found by the user walkthrough).
- Dead temp-dir allocation removed from the attest self-test.
- Governance timeline test made timezone-hermetic (asserted timestamp
  structure instead of a local-year prefix; previously failed on UTC−4).

### Security
- Hard-purge markers record the erasure pattern as a **SHA-256 digest**
  (`erasure:sha256:<hex>`) instead of verbatim — erasing by a literal secret no
  longer re-embeds it in the audit trail (D6).
- Key loaders now refuse empty/whitespace-only keys from `--key`, keyfiles, or env vars instead of
  silently downgrading HMAC to plain SHA-256; inline key flags emit a stderr warning
  (visible in `ps`/shell history — prefer keyfile or env). (CodeRabbit R1)

## [0.1.0] — 2026-07-02

### Added
- Initial public release: hash-chained, tamper-evident attestation
  (`amem_attest.py`, SHA-256 with optional HMAC), external root anchoring
  (`amem_anchor.py`), and the governance CLI (`amem_governance.py`: audit,
  lineage, conflicts, GDPR erasure, retention, summary, attest/verify-chain).
- 38-test suite (attest known-answer vectors + independent stdlib verifier;
  anchor round-trips) and the `ATTESTATION.md` spec & threat model.
- Published to PyPI as **`atelya-attest`**; Apache-2.0.
