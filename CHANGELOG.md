# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Staged as **0.1.1** (version bumped in `pyproject.toml`; not yet on PyPI).

### Added
- `tests/test_amem_governance.py`: 22-case suite covering replay/supersede,
  GDPR **soft-forget vs hard-purge** (purge itself logged; the marker's
  `reason` records the erasure *pattern* verbatim — erase by label, not by
  pasting the literal secret), retention by age and by active-cap
  (oldest-first), audit timeline/export, lineage, conflict winners, CLI guard
  exits, and an attest → verify-chain → tamper round-trip. Total suite: **60**.
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
- Dead temp-dir allocation removed from the attest self-test.
- Governance timeline test made timezone-hermetic (asserted timestamp
  structure instead of a local-year prefix; previously failed on UTC−4).

### Security
- Key loaders now refuse empty keys from `--key`, keyfiles, or env vars instead of
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
