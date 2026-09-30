# Changelog

All notable changes to traust-engine are documented here.

## [0.17.0]

## Changes

- **`locations.analysis_results` chooses where reports live.** A path or
  `file://` stays on local disk; an `s3://` / `gs://` URI goes through fsspec
  (`traust-engine[s3]` / `[gcs]`, configured by the existing `HARNESS_S3_*`
  env). New `report_store.open_backend(location)` picks the backend and
  `FsspecBackend` implements it; `engine.corpus.report_store()` and
  `corpus.precedent` use it instead of hard-coding `LocalBackend`.
  `storage.filesystem(uri)` is public, and a missing scheme driver is a
  `StorageError` naming the extra rather than fsspec's `ImportError`.
- Remote `analysis_results` covers verified reads and writes through
  `ReportStore`; ingest and resolution still walk a local tree.
- `FsspecBackend` failures are `StorageError`, never "absent": `exists()` no
  longer returns `False` on bad credentials or an unreachable endpoint,
  `list()` wraps backend errors, and a missing bucket fails at construction
  instead of reading as "report not found". Only writable schemes (`s3`,
  `gs`/`gcs`, `az`/`abfs`) are accepted as a report location; `http(s)://` is
  refused up front. `SoundnessResolver` refuses a remote `analysis_results`
  (precedent resolution is local-only) instead of treating `s3://b/p` as a
  local folder.
- Pins: traust-contracts 0.44.0 (from 0.35.0), traust-ledger 0.8.1 (from
  0.6.32).
- **Consumers: ledger writes now need a verifiable identity.** Ledger ≥0.7
  verifies the actor before `sign()` / `patch_metadata()` /
  `stamp_event_identities()`, so a placeholder token (`token="test-token"`)
  is refused. Configure OIDC (`LEDGER_OIDC_ISSUER` / `LEDGER_OIDC_JWKS_URL`)
  or local auth (`LEDGER_LOCAL_IDENTITY`, or `ledger auth local`); test
  suites can set `LEDGER_LOCAL_IDENTITY` in an isolated `HOME`. Ledger 0.8
  also refuses to sign a layer without an initialized shell (`audit_report`,
  `repository`, `created`, `harness_version`). `finding_identity.rebaseline`
  is unchanged; its tests now supply a verifier, a complete layer shell, and
  sha256-shaped claim hashes.

## [0.3.0]

## Changes

- **Reverted the 0.15.0 findings.db changes.** `findings_db` builds the
  previous nine-table projection again (`SCHEMA_REVISION` 3), `store_ingest`
  and the SLA view are as in 0.13.3. Pins: contracts 0.35.0 (the 0.33.0
  storage contract), ledger 0.6.32. 0.15.0 remains tagged and should not be
  pinned.

## [0.2.5]

- Pin traust-contracts v0.5.0 (evidence projection + postgres storage
  namespace) and traust-ledger v0.3.0 (stamp + whoami over REST).

## [0.2.4]

- Point the traust-contracts and traust-ledger pins at the new
  `traust-security` GitHub organisation (ledger v0.2.3, which carries the
  corrected URL inside its own tag).

## [0.2.3]

- Pin traust-contracts v0.4.0 and traust-ledger v0.2.2, carrying the typed
  patch-evidence block on the VERIFICATION family through to the report
  validator. No engine logic changes: `reporting/validate.py` validates
  against the pinned schema, so accepting the block on a verification report
  is a consequence of the pin.

## [0.2.2]

- Pin traust-contracts v0.3.0 and traust-ledger v0.2.1, carrying the optional
  `evidence[]` block on remediation reports through to the report validator.
  No engine logic changes: `reporting/validate.py` validates against the
  pinned schema, so accepting the block is a consequence of the pin. The
  existing cross-check tying `summary.status == 'revalidated_fixed'` to
  `revalidation.fixed` is untouched, since no status depends on `evidence[]`
  yet.

## [0.2.0]

## Changes

- delegate countersign/whoami/stamp_event_identities to the engine

## [0.1.1]

## Changes

- Adopt traust-contracts 0.1.1 and traust-ledger 0.1.1, which enforce RFC
  3339 on `LayerEvent.recorded_at` / `.occurred_at`. No engine code changes
  were needed — dependency pins only.

### Upgrading

Contracts 0.1.1 validates timestamps on read as well as write, so a corpus
holding non-conforming values must be migrated before this release is used
against it (`python3 -m traust.migrations.fix_event_timestamps <root>
--apply`). `traust_engine.reporting.validate` also asserts `format:
date-time` now that the format assertor ships as a declared dependency.

## [0.1.0]

Self-contained processing library for Traust: deterministic workflow code
for disposition merge, validation gates, and rule calibration — the
`traust_engine` package consumed by the app CLI and other components.
