# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
