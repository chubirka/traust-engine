"""`LedgerService.restate()` and `stamp_report_file()` against ledger >=0.8.

A signed digest may only change through a restatement that records the prior
value, the actor, a ticket and a rationale; `patch_metadata` refuses the
overwrite. These tests pin the engine seam to that contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from traust_contracts.v1.models.layer import LayerActor
from traust_ledger.client import LedgerClient, LedgerError

from traust_engine.ledger import LedgerService, report_sha256

OLD, NEW = "a" * 64, "b" * 64
RATIONALE = "Finding revised after reproduction; claim re-baselined."


class _Verifier:
    def verify(self, token: str) -> LayerActor:
        return LayerActor(kind="human", identity="analyst@example.com", identity_verified=True)


def _service(tmp_path: Path, **metadata) -> tuple[LedgerService, Path]:
    layer_path = tmp_path / "repo-findings-layer.json"
    shell = {
        "audit_report": "repo-security-audit.json",
        "repository": "https://github.com/org/repo",
        "created": "2026-09-01T00:00:00+00:00",
        "harness_version": "0.298.0",
    }
    layer_path.write_text(
        json.dumps({"metadata": shell | metadata, "events": [], "needs_review": []})
    )
    service = LedgerService(LedgerClient(data_dir=str(tmp_path), verifier=_Verifier()))
    service.sign(layer_path)
    return service, layer_path


def _layer(path: Path) -> dict:
    return json.loads(path.read_text())


def test_restate_overwrites_a_signed_claim_hash_and_records_it(tmp_path: Path) -> None:
    service, lp = _service(tmp_path, claim_hashes={"FIND-001": OLD})
    with pytest.raises(LedgerError, match="use restate"):
        service.patch_layer_file(lp, {"claim_hashes": {"FIND-001": NEW}})

    service.restate(
        lp,
        target="claim_hashes",
        before={"FIND-001": OLD},
        after={"FIND-001": NEW},
        ticket="XWING-1",
        rationale=RATIONALE,
    )
    layer = _layer(lp)
    assert layer["metadata"]["claim_hashes"] == {"FIND-001": NEW}
    (event,) = layer["events"]
    assert event["restatement"]["before"] == {"FIND-001": OLD}
    assert event["restatement"]["reason"] == "baseline_rewrite"
    assert event["restatement"]["authority"] == {"ticket": "XWING-1"}
    assert event["source"]["actor"]["identity"] == "analyst@example.com"


def test_restate_refuses_a_stale_before(tmp_path: Path) -> None:
    service, lp = _service(tmp_path, claim_hashes={"FIND-001": OLD})
    with pytest.raises(LedgerError, match="does not match the stored value"):
        service.restate(
            lp,
            target="claim_hashes",
            before={"FIND-001": "9" * 64},
            after={"FIND-001": NEW},
            ticket="XWING-1",
            rationale=RATIONALE,
        )
    assert _layer(lp)["events"] == []


def test_stamp_report_file_pins_once_and_refuses_an_overwrite(tmp_path: Path) -> None:
    service, lp = _service(tmp_path)
    report = tmp_path / "repo-security-audit.json"
    report.write_text('{"findings": []}')

    assert service.stamp_report_file(lp, report) is True
    assert service.stamp_report_file(lp, report) is False

    original = report_sha256(str(report))
    report.write_text('{"findings": [], "reissued": true}')
    with pytest.raises(LedgerError, match="restate"):
        service.stamp_report_file(lp, report)
    assert _layer(lp)["metadata"]["audit_report_sha256"] == original

    service.restate(
        lp,
        target="audit_report_sha256",
        before=original,
        after=report_sha256(str(report)),
        ticket="XWING-2",
        rationale="Audit report reissued after the corrected finding was revised.",
    )
    assert service.stamp_report_file(lp, report) is False
