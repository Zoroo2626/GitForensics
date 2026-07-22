"""Transparent repository risk score calculation module."""

import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from gitforensics.models import Confidence, Finding, Severity

SEVERITY_ORDER = MappingProxyType(
    {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
)
RULE_TO_GROUP = MappingProxyType(
    {
        "GF002": "GF002_GF003",
        "GF003": "GF002_GF003",
        "GF001": "GF001_GF010",
        "GF010": "GF001_GF010",
        "GF004": "GF004_GF005",
        "GF005": "GF004_GF005",
        "GF008": "GF008_GF009",
        "GF009": "GF008_GF009",
        "GF011": "GF011_GF012",
        "GF012": "GF011_GF012",
        "GF013": "GF013_GF015",
        "GF015": "GF013_GF015",
        "GF014": "GF014_GF016",
        "GF016": "GF014_GF016",
    }
)


def finding_sort_key(finding: Finding) -> tuple[str, int, str, str]:
    """Return the single stable ordering key used by orchestration and scoring."""
    return (
        finding.rule_id,
        SEVERITY_ORDER.get(finding.severity, 99),
        finding.title,
        finding.description,
    )


@dataclass
class ScoringConfig:
    """Typed configuration model for scoring weights, multipliers, and caps."""

    base_weights: dict[Severity, float] = field(
        default_factory=lambda: {
            Severity.CRITICAL: 30.0,
            Severity.HIGH: 15.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.0,
        }
    )
    confidence_multipliers: dict[Confidence, float] = field(
        default_factory=lambda: {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.7,
            Confidence.LOW: 0.4,
        }
    )
    grouping_caps: dict[str, float] = field(
        default_factory=lambda: {
            "GF002_GF003": 25.0,  # Regular intervals + Commit bursts
            "GF001_GF010": 20.0,  # Initial import + Repo age
            "GF004_GF005": 20.0,  # Contributor concentration + Identity mismatches
            "GF008_GF009": 30.0,  # History workflows + Tag anomalies
            "GF011_GF012": 20.0,  # Release unresolvable + Repeated targets
            "GF013_GF015": 15.0,  # Chronology conflict + Mutable asset
            "GF014_GF016": 20.0,  # Asset heavy + Digest/attestation
        }
    )

    def validate(self) -> None:
        """Validates configuration values and raises ValueError if invalid."""
        for sev, weight in self.base_weights.items():
            if weight < 0:
                raise ValueError(f"Base weight for severity {sev} cannot be negative.")
        for conf, mult in self.confidence_multipliers.items():
            if mult < 0.0 or mult > 1.0:
                raise ValueError(f"Confidence multiplier for {conf} must be between 0.0 and 1.0.")
        for group, cap in self.grouping_caps.items():
            if cap <= 0:
                raise ValueError(f"Grouping cap for {group} must be greater than zero.")


@dataclass
class ScoreExplanation:
    """Detailed explanation of final score calculation and rules applied."""

    score: int
    assessment_label: str
    is_complete: bool
    base_score: int
    formula: str
    finding_contributions: list[dict[str, Any]] = field(default_factory=list)
    applied_groupings_and_caps: list[str] = field(default_factory=list)
    excluded_findings: list[dict[str, Any]] = field(default_factory=list)
    max_possible_score: int = 100
    scoring_model_version: str = "1.0.0"

    @property
    def details(self) -> str:
        """Compatibility property for findings detail summary."""
        return f"Calculated from {len(self.finding_contributions)} finding(s)."

    def to_dict(self) -> dict[str, Any]:
        """Serialize ScoreExplanation to JSON-serializable dictionary."""
        return {
            "score": self.score,
            "assessment_label": self.assessment_label,
            "is_complete": self.is_complete,
            "base_score": self.base_score,
            "formula": self.formula,
            "details": self.details,
            "finding_contributions": self.finding_contributions,
            "applied_groupings_and_caps": self.applied_groupings_and_caps,
            "excluded_findings": self.excluded_findings,
            "max_possible_score": self.max_possible_score,
            "scoring_model_version": self.scoring_model_version,
        }


def get_assessment_label(score: int) -> str:
    """Returns assessment concern label based on numeric score."""
    if score <= 15:
        return "Low observed concern"
    elif score <= 35:
        return "Moderate observed concern"
    elif score <= 65:
        return "Elevated observed concern"
    else:
        return "High observed concern"


def calculate_risk_score(
    findings: list[Finding],
    is_complete: bool = True,
    config: ScoringConfig | None = None,
) -> ScoreExplanation:
    """Calculates a transparent, deterministic risk score (0-100) from findings."""
    scoring_config = config or ScoringConfig()
    scoring_config.validate()

    formula_str = "Score = MIN(100, SUM(Capped_Groups) + SUM(Individual_Weighted_Findings))"

    if not findings:
        return ScoreExplanation(
            score=0,
            assessment_label=get_assessment_label(0),
            is_complete=is_complete,
            base_score=0,
            formula=formula_str,
            finding_contributions=[],
            applied_groupings_and_caps=[],
            excluded_findings=[],
        )

    already_sorted = all(
        finding_sort_key(findings[index - 1]) <= finding_sort_key(findings[index])
        for index in range(1, len(findings))
    )
    sorted_findings = findings if already_sorted else sorted(findings, key=finding_sort_key)

    contributions: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    applied_caps: list[str] = []

    groups: dict[str, list[tuple[Finding, float]]] = {
        "GF002_GF003": [],
        "GF001_GF010": [],
        "GF004_GF005": [],
        "GF008_GF009": [],
        "GF011_GF012": [],
        "GF013_GF015": [],
        "GF014_GF016": [],
    }
    unbound_raw_sum = 0.0

    for f in sorted_findings:
        base_w = scoring_config.base_weights.get(f.severity, 0.0)
        conf_m = scoring_config.confidence_multipliers.get(f.confidence, 1.0)
        weighted_val = base_w * conf_m
        unbound_raw_sum += weighted_val

        if f.severity == Severity.INFO or weighted_val == 0.0:
            excluded.append(
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "reason": "Informational findings have 0 base score weight.",
                }
            )
            continue

        grp_key = RULE_TO_GROUP.get(f.rule_id)
        if grp_key:
            groups[grp_key].append((f, weighted_val))
        else:
            contributions.append(
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "base_weight": base_w,
                    "confidence_multiplier": conf_m,
                    "weighted_contribution": round(weighted_val, 2),
                }
            )

    total_score_sum = sum(c["weighted_contribution"] for c in contributions)

    # Process grouped caps (only when multiple distinct rules in group are present)
    for grp_key, grp_items in groups.items():
        if not grp_items:
            continue

        distinct_rules = {item[0].rule_id for item in grp_items}
        cap_limit = scoring_config.grouping_caps.get(grp_key, 100.0)
        grp_raw_sum = sum(item[1] for item in grp_items)

        if len(distinct_rules) > 1 and grp_raw_sum > cap_limit:
            applied_caps.append(
                f"Group {grp_key} capped at {cap_limit} points (raw sum: {round(grp_raw_sum, 2)})"
            )
            capped_grp_score = cap_limit
        else:
            capped_grp_score = grp_raw_sum

        total_score_sum += capped_grp_score

        for f, w_val in grp_items:
            contributions.append(
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "base_weight": scoring_config.base_weights.get(f.severity, 0.0),
                    "confidence_multiplier": scoring_config.confidence_multipliers.get(
                        f.confidence, 1.0
                    ),
                    "weighted_contribution": round(w_val, 2),
                    "group": grp_key,
                }
            )

    base_score_int = int(math.ceil(unbound_raw_sum))
    # Standard half-up rounding
    final_numeric_score = min(100, max(0, int(math.floor(total_score_sum + 0.5))))

    label = get_assessment_label(final_numeric_score)

    return ScoreExplanation(
        score=final_numeric_score,
        assessment_label=label,
        is_complete=is_complete,
        base_score=base_score_int,
        formula=formula_str,
        finding_contributions=contributions,
        applied_groupings_and_caps=applied_caps,
        excluded_findings=excluded,
    )
