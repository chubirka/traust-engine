"""OWASP Risk Rating for threat-model tables, and one ordering for the fleet.

Threats are rated with the OWASP Risk Rating Methodology (OWASP Foundation,
https://owasp.org/www-community/OWASP_Risk_Rating_Methodology, CC BY-SA 4.0).
The arithmetic -- factor means, levels, the severity table -- lives in
`traust_contracts.v1.risk_rating` and is not repeated here. This module owns
how a rating is WRITTEN in the rendered Markdown and read back from it:

- Section 4 of a rated model carries `severity | likelihood | impact` in
  place of the legacy `impact | likelihood` pair. A likelihood cell is
  `<level> <score>` (`medium 4.375`); an impact cell adds the basis
  (`high 7.25 technical`). A threat not yet re-rated keeps its legacy labels
  as `legacy <label>` under severity `unrated`.
- Section 11 lists every factor score, so a reviewer can check the rating
  and the linter can recompute it.

Legacy labels (impact low..existential, likelihood very_rare..almost_certain)
are not OWASP values. Until every model is re-rated, the fleet still has to
be put in one order, so `legacy_severity` maps legacy labels onto OWASP
levels for ORDERING ONLY. The mapping is never written back as a rating, and
every consumer reports it as `severity_source: legacy-crosswalk`.
"""

from __future__ import annotations

import re
from typing import Any

from traust_contracts.v1 import risk_rating as rr

SEVERITY_ORDER = tuple(reversed(rr.SEVERITIES))  # critical .. note
UNRATED = "unrated"

LEGACY_IMPACT = ("low", "medium", "high", "critical", "existential")
LEGACY_LIKELIHOOD = ("very_rare", "rare", "possible", "likely", "almost_certain")

#: Legacy label -> OWASP level, for ordering unrated threats beside rated
#: ones. Each legacy scale has five labels and OWASP three levels; the top
#: labels share `high` because OWASP has nothing above it.
LEGACY_IMPACT_LEVEL = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "high",
    "existential": "high",
}
LEGACY_LIKELIHOOD_LEVEL = {
    "very_rare": "low",
    "rare": "low",
    "possible": "medium",
    "likely": "high",
    "almost_certain": "high",
}

_SCORE = r"(\d(?:\.\d{1,3})?)"
LIKELIHOOD_CELL = re.compile(rf"^(low|medium|high) {_SCORE}$")
IMPACT_CELL = re.compile(rf"^(low|medium|high) {_SCORE} (technical|business)$")
LEGACY_CELL = re.compile(r"^legacy (\S+)$")

FACTOR_COLUMNS = ["factor", "score", "reason"]
RATING_HEADING = re.compile(r"^### (T\d+)\b")
ALL_FACTORS = (
    *rr.LIKELIHOOD_FACTORS,
    *rr.TECHNICAL_IMPACT_FACTORS,
    *rr.BUSINESS_IMPACT_FACTORS,
)


def format_score(score: float) -> str:
    """A score as written in a cell: up to three decimals, no trailing zeros."""
    return f"{score:.3f}".rstrip("0").rstrip(".")


def likelihood_cell(rating: dict) -> str:
    likelihood = rating["likelihood"]
    return f"{likelihood['level']} {format_score(likelihood['score'])}"


def impact_cell(rating: dict) -> str:
    impact = rating["impact"]
    return f"{impact['level']} {format_score(impact['score'])} {impact['basis']}"


def threat_cells(threat: dict) -> dict[str, str]:
    """The severity, likelihood and impact cells for one JSON threat."""
    rating = threat.get("risk_rating")
    if rating:
        return {
            "severity": rating["severity"],
            "likelihood": likelihood_cell(rating),
            "impact": impact_cell(rating),
        }
    return {
        "severity": UNRATED,
        "likelihood": f"legacy {threat.get('likelihood', '')}".strip(),
        "impact": f"legacy {threat.get('impact', '')}".strip(),
    }


def legacy_severity(impact: str | None, likelihood: str | None) -> str | None:
    """The OWASP severity legacy labels ORDER as, or None if either is unknown."""
    i_level = LEGACY_IMPACT_LEVEL.get(impact or "")
    l_level = LEGACY_LIKELIHOOD_LEVEL.get(likelihood or "")
    if i_level is None or l_level is None:
        return None
    return rr.severity(i_level, l_level)


def cell_problems(severity: str, likelihood: str, impact: str) -> list[str]:
    """Every way a rated table row's three cells disagree with each other.

    The cells carry levels AND scores, so they must agree: each level must be
    the one its score falls in, and severity must be what the table gives for
    the two levels. The factor check (section 11) is separate.
    """
    if severity == UNRATED:
        found = []
        lm, im = LEGACY_CELL.match(likelihood), LEGACY_CELL.match(impact)
        if not lm or lm.group(1) not in LEGACY_LIKELIHOOD:
            found.append(
                f"likelihood '{likelihood}' must be 'legacy <label>' with a label "
                f"in {list(LEGACY_LIKELIHOOD)} when severity is '{UNRATED}'"
            )
        if not im or im.group(1) not in LEGACY_IMPACT:
            found.append(
                f"impact '{impact}' must be 'legacy <label>' with a label "
                f"in {list(LEGACY_IMPACT)} when severity is '{UNRATED}'"
            )
        return found
    if severity not in rr.SEVERITIES:
        return [f"severity '{severity}' not in {[*SEVERITY_ORDER, UNRATED]}"]
    lm, im = LIKELIHOOD_CELL.match(likelihood), IMPACT_CELL.match(impact)
    found = []
    if not lm:
        found.append(f"likelihood '{likelihood}' must be '<low|medium|high> <score 0-9>'")
    if not im:
        found.append(
            f"impact '{impact}' must be '<low|medium|high> <score 0-9> <technical|business>'"
        )
    if found:
        return found
    for name, match in (("likelihood", lm), ("impact", im)):
        want = rr.level(float(match.group(2)))
        if match.group(1) != want:
            found.append(
                f"{name} level '{match.group(1)}' should be '{want}' for score {match.group(2)}"
            )
    if not found:
        want = rr.severity(im.group(1), lm.group(1))
        if severity != want:
            found.append(
                f"severity '{severity}' should be '{want}' for impact "
                f"{im.group(1)} and likelihood {lm.group(1)}"
            )
    return found


def parse_row(row: dict[str, str]) -> dict[str, Any]:
    """Rating fields from one section 4 row, of either table variant.

    Returns `severity` (None when legacy labels are unknown),
    `severity_source` (`owasp`, `legacy-crosswalk` or None), `likelihood` and
    `impact` (an OWASP level, or the legacy label), and for rated rows
    `likelihood_score`, `impact_score` and `impact_basis`.
    """
    if "severity" not in row:
        impact, likelihood = row.get("impact", ""), row.get("likelihood", "")
        severity = legacy_severity(impact, likelihood)
        return {
            "severity": severity,
            "severity_source": "legacy-crosswalk" if severity else None,
            "likelihood": likelihood,
            "impact": impact,
        }
    if row["severity"] == UNRATED:
        lm = LEGACY_CELL.match(row.get("likelihood", ""))
        im = LEGACY_CELL.match(row.get("impact", ""))
        likelihood = lm.group(1) if lm else ""
        impact = im.group(1) if im else ""
        severity = legacy_severity(impact, likelihood)
        return {
            "severity": severity,
            "severity_source": "legacy-crosswalk" if severity else None,
            "likelihood": likelihood,
            "impact": impact,
        }
    lm = LIKELIHOOD_CELL.match(row.get("likelihood", ""))
    im = IMPACT_CELL.match(row.get("impact", ""))
    if not lm or not im or row["severity"] not in rr.SEVERITIES:
        return {
            "severity": None,
            "severity_source": None,
            "likelihood": row.get("likelihood", ""),
            "impact": row.get("impact", ""),
        }
    return {
        "severity": row["severity"],
        "severity_source": "owasp",
        "likelihood": lm.group(1),
        "impact": im.group(1),
        "likelihood_score": float(lm.group(2)),
        "impact_score": float(im.group(2)),
        "impact_basis": im.group(3),
    }


def threat_severity(threat: dict) -> tuple[str | None, str | None]:
    """(severity, source) for one JSON threat: its rating, else the crosswalk."""
    rating = threat.get("risk_rating")
    if rating:
        return rating.get("severity"), "owasp"
    severity = legacy_severity(threat.get("impact"), threat.get("likelihood"))
    return severity, ("legacy-crosswalk" if severity else None)


def order_key(parsed: dict) -> tuple:
    """Sort key, most severe first: severity, then rated before crosswalked,
    then impact score and likelihood score (rated rows only)."""
    return (
        -rr.severity_rank(parsed.get("severity")),
        0 if parsed.get("severity_source") == "owasp" else 1,
        -(parsed.get("impact_score") or 0.0),
        -(parsed.get("likelihood_score") or 0.0),
    )


# ---------------------------------------------------------------------------
# Section 11: the factor scores behind each rating
# ---------------------------------------------------------------------------


def factor_rows(rating: dict) -> list[dict[str, str]]:
    """Section 11 table rows for one rating, in method order."""
    reasons = rating.get("rationale") or {}
    scores = dict(rating["likelihood"]["factors"])
    scores.update(rating["impact"]["technical"])
    scores.update(rating["impact"].get("business") or {})
    return [
        {"factor": name, "score": str(scores[name]), "reason": reasons.get(name, "")}
        for name in ALL_FACTORS
        if name in scores
    ]


def rating_from_factors(
    scores: dict[str, int], basis: str
) -> tuple[dict[str, Any] | None, list[str]]:
    """Recompute a rating from section 11 factor scores: (rating, problems)."""
    found = []
    missing = [n for n in (*rr.LIKELIHOOD_FACTORS, *rr.TECHNICAL_IMPACT_FACTORS) if n not in scores]
    if basis == "business":
        missing += [n for n in rr.BUSINESS_IMPACT_FACTORS if n not in scores]
    if missing:
        found.append(f"missing factor(s) {missing}")
    business_given = [n for n in rr.BUSINESS_IMPACT_FACTORS if n in scores]
    if business_given and len(business_given) != len(rr.BUSINESS_IMPACT_FACTORS):
        found.append(f"business factors must be all present or all absent, got {business_given}")
    if found:
        return None, found
    business = {n: scores[n] for n in rr.BUSINESS_IMPACT_FACTORS} if business_given else None
    try:
        rating = rr.rate(
            {n: scores[n] for n in rr.LIKELIHOOD_FACTORS},
            {n: scores[n] for n in rr.TECHNICAL_IMPACT_FACTORS},
            business,
            basis=basis,
        )
    except ValueError as exc:
        return None, [str(exc)]
    return rating, []
