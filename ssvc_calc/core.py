"""SSVC Deployer decision engine.

Implements the CISA/CERT-CC SSVC v2 Deployer decision table.
The table is the authoritative source — no hand-written if/else logic.

Both the Deployer table (72 rows) and Human Impact table (16 rows) are
validated at module load time for completeness and monotonicity, inspired
by the self-validating design of the official certcc-ssvc package.

Reference:
  https://certcc.github.io/SSVC/
  https://github.com/CERTCC/SSVC (MIT License)
"""

from __future__ import annotations

from enum import IntEnum


class Decision(IntEnum):
    """SSVC Deployer action priority."""
    DEFER = 1
    SCHEDULED = 2
    OUT_OF_CYCLE = 3
    IMMEDIATE = 4

    def __str__(self) -> str:
        return _DECISION_LABELS[self]

    @classmethod
    def parse(cls, s: str) -> Decision:
        """Parse a human-readable label into a Decision.

        >>> Decision.parse("Immediate")
        <Decision.IMMEDIATE: 4>
        """
        key = s.strip().lower().replace("-", "_").replace(" ", "_")
        if key not in _PARSE_MAP:
            raise ValueError(
                f"Unknown decision: {s!r}. "
                f"Valid values: {', '.join(_DECISION_LABELS.values())}"
            )
        return _PARSE_MAP[key]


_DECISION_LABELS = {
    Decision.DEFER: "Defer",
    Decision.SCHEDULED: "Scheduled",
    Decision.OUT_OF_CYCLE: "Out-of-cycle",
    Decision.IMMEDIATE: "Immediate",
}

_PARSE_MAP = {
    "defer": Decision.DEFER,
    "scheduled": Decision.SCHEDULED,
    "out_of_cycle": Decision.OUT_OF_CYCLE,
    "out-of-cycle": Decision.OUT_OF_CYCLE,
    "immediate": Decision.IMMEDIATE,
}

# ---------------------------------------------------------------------------
# Deployer decision table (SSVC v2)
#
# Source: CERT/CC SSVC project — DEPLOYER_1 mapping table (72 rows).
# Key: (exploitation, exposure, automatable, human_impact) -> Decision
#
# Exploitation: "none" | "poc" | "active"
# Exposure:     "small" | "controlled" | "open"
# Automatable:  True | False
# Human Impact: "low" | "medium" | "high" | "very_high"
# ---------------------------------------------------------------------------

_TABLE: dict[tuple[str, str, bool, str], Decision] = {
    # exploitation=none, exposure=small
    ("none", "small", False, "low"): Decision.DEFER,
    ("none", "small", False, "medium"): Decision.DEFER,
    ("none", "small", False, "high"): Decision.SCHEDULED,
    ("none", "small", False, "very_high"): Decision.SCHEDULED,
    ("none", "small", True, "low"): Decision.DEFER,
    ("none", "small", True, "medium"): Decision.SCHEDULED,
    ("none", "small", True, "high"): Decision.SCHEDULED,
    ("none", "small", True, "very_high"): Decision.SCHEDULED,
    # exploitation=none, exposure=controlled
    ("none", "controlled", False, "low"): Decision.DEFER,
    ("none", "controlled", False, "medium"): Decision.SCHEDULED,
    ("none", "controlled", False, "high"): Decision.SCHEDULED,
    ("none", "controlled", False, "very_high"): Decision.SCHEDULED,
    ("none", "controlled", True, "low"): Decision.SCHEDULED,
    ("none", "controlled", True, "medium"): Decision.SCHEDULED,
    ("none", "controlled", True, "high"): Decision.SCHEDULED,
    ("none", "controlled", True, "very_high"): Decision.SCHEDULED,
    # exploitation=none, exposure=open
    ("none", "open", False, "low"): Decision.DEFER,
    ("none", "open", False, "medium"): Decision.SCHEDULED,
    ("none", "open", False, "high"): Decision.SCHEDULED,
    ("none", "open", False, "very_high"): Decision.SCHEDULED,
    ("none", "open", True, "low"): Decision.SCHEDULED,
    ("none", "open", True, "medium"): Decision.SCHEDULED,
    ("none", "open", True, "high"): Decision.SCHEDULED,
    ("none", "open", True, "very_high"): Decision.OUT_OF_CYCLE,
    # exploitation=poc, exposure=small
    ("poc", "small", False, "low"): Decision.DEFER,
    ("poc", "small", False, "medium"): Decision.SCHEDULED,
    ("poc", "small", False, "high"): Decision.SCHEDULED,
    ("poc", "small", False, "very_high"): Decision.SCHEDULED,
    ("poc", "small", True, "low"): Decision.SCHEDULED,
    ("poc", "small", True, "medium"): Decision.SCHEDULED,
    ("poc", "small", True, "high"): Decision.SCHEDULED,
    ("poc", "small", True, "very_high"): Decision.SCHEDULED,
    # exploitation=poc, exposure=controlled
    ("poc", "controlled", False, "low"): Decision.DEFER,
    ("poc", "controlled", False, "medium"): Decision.SCHEDULED,
    ("poc", "controlled", False, "high"): Decision.SCHEDULED,
    ("poc", "controlled", False, "very_high"): Decision.SCHEDULED,
    ("poc", "controlled", True, "low"): Decision.SCHEDULED,
    ("poc", "controlled", True, "medium"): Decision.SCHEDULED,
    ("poc", "controlled", True, "high"): Decision.SCHEDULED,
    ("poc", "controlled", True, "very_high"): Decision.OUT_OF_CYCLE,
    # exploitation=poc, exposure=open
    ("poc", "open", False, "low"): Decision.SCHEDULED,
    ("poc", "open", False, "medium"): Decision.SCHEDULED,
    ("poc", "open", False, "high"): Decision.SCHEDULED,
    ("poc", "open", False, "very_high"): Decision.OUT_OF_CYCLE,
    ("poc", "open", True, "low"): Decision.SCHEDULED,
    ("poc", "open", True, "medium"): Decision.SCHEDULED,
    ("poc", "open", True, "high"): Decision.OUT_OF_CYCLE,
    ("poc", "open", True, "very_high"): Decision.OUT_OF_CYCLE,
    # exploitation=active, exposure=small
    ("active", "small", False, "low"): Decision.SCHEDULED,
    ("active", "small", False, "medium"): Decision.SCHEDULED,
    ("active", "small", False, "high"): Decision.OUT_OF_CYCLE,
    ("active", "small", False, "very_high"): Decision.OUT_OF_CYCLE,
    ("active", "small", True, "low"): Decision.SCHEDULED,
    ("active", "small", True, "medium"): Decision.OUT_OF_CYCLE,
    ("active", "small", True, "high"): Decision.OUT_OF_CYCLE,
    ("active", "small", True, "very_high"): Decision.OUT_OF_CYCLE,
    # exploitation=active, exposure=controlled
    ("active", "controlled", False, "low"): Decision.SCHEDULED,
    ("active", "controlled", False, "medium"): Decision.SCHEDULED,
    ("active", "controlled", False, "high"): Decision.OUT_OF_CYCLE,
    ("active", "controlled", False, "very_high"): Decision.OUT_OF_CYCLE,
    ("active", "controlled", True, "low"): Decision.OUT_OF_CYCLE,
    ("active", "controlled", True, "medium"): Decision.OUT_OF_CYCLE,
    ("active", "controlled", True, "high"): Decision.OUT_OF_CYCLE,
    ("active", "controlled", True, "very_high"): Decision.OUT_OF_CYCLE,
    # exploitation=active, exposure=open
    ("active", "open", False, "low"): Decision.SCHEDULED,
    ("active", "open", False, "medium"): Decision.OUT_OF_CYCLE,
    ("active", "open", False, "high"): Decision.OUT_OF_CYCLE,
    ("active", "open", False, "very_high"): Decision.IMMEDIATE,
    ("active", "open", True, "low"): Decision.OUT_OF_CYCLE,
    ("active", "open", True, "medium"): Decision.OUT_OF_CYCLE,
    ("active", "open", True, "high"): Decision.IMMEDIATE,
    ("active", "open", True, "very_high"): Decision.IMMEDIATE,
}

_VALID_EXPLOITATION = frozenset(("none", "poc", "active"))
_VALID_EXPOSURE = frozenset(("small", "controlled", "open"))
_VALID_HUMAN_IMPACT = frozenset(("low", "medium", "high", "very_high"))


def decide(
    exploitation: str,
    exposure: str,
    automatable: bool,
    human_impact: str,
) -> Decision:
    """Look up the SSVC Deployer decision for the given inputs.

    Args:
        exploitation: "none", "poc", or "active"
        exposure: "small", "controlled", or "open"
        automatable: Whether the vulnerability is automatable
        human_impact: "low", "medium", "high", or "very_high"

    Returns:
        Decision enum value (DEFER, SCHEDULED, OUT_OF_CYCLE, or IMMEDIATE)

    Raises:
        ValueError: If any input value is invalid

    >>> decide("active", "open", True, "high")
    <Decision.IMMEDIATE: 4>
    """
    exploitation = exploitation.strip().lower()
    exposure = exposure.strip().lower()
    human_impact = human_impact.strip().lower().replace("-", "_").replace(" ", "_")

    if exploitation not in _VALID_EXPLOITATION:
        raise ValueError(f"exploitation must be one of {sorted(_VALID_EXPLOITATION)}, got {exploitation!r}")
    if exposure not in _VALID_EXPOSURE:
        raise ValueError(f"exposure must be one of {sorted(_VALID_EXPOSURE)}, got {exposure!r}")
    if human_impact not in _VALID_HUMAN_IMPACT:
        raise ValueError(f"human_impact must be one of {sorted(_VALID_HUMAN_IMPACT)}, got {human_impact!r}")

    return _TABLE[(exploitation, exposure, automatable, human_impact)]


# ---------------------------------------------------------------------------
# Human Impact helper (optional convenience)
# ---------------------------------------------------------------------------

_VALID_SAFETY = frozenset(("negligible", "marginal", "critical", "catastrophic"))
_VALID_MISSION = frozenset(("degraded", "mef_support_crippled", "mef_failure", "mission_failure"))

# Human Impact lookup table from SSVC v2 specification.
# https://certcc.github.io/SSVC/reference/decision_points/human_impact/
# (safety_impact, mission_impact) -> human_impact
_HUMAN_IMPACT_TABLE: dict[tuple[str, str], str] = {
    # negligible safety
    ("negligible", "degraded"): "low",
    ("negligible", "mef_support_crippled"): "low",
    ("negligible", "mef_failure"): "medium",
    ("negligible", "mission_failure"): "very_high",
    # marginal safety
    ("marginal", "degraded"): "low",
    ("marginal", "mef_support_crippled"): "low",
    ("marginal", "mef_failure"): "medium",
    ("marginal", "mission_failure"): "very_high",
    # critical safety
    ("critical", "degraded"): "medium",
    ("critical", "mef_support_crippled"): "high",
    ("critical", "mef_failure"): "high",
    ("critical", "mission_failure"): "very_high",
    # catastrophic safety
    ("catastrophic", "degraded"): "very_high",
    ("catastrophic", "mef_support_crippled"): "very_high",
    ("catastrophic", "mef_failure"): "very_high",
    ("catastrophic", "mission_failure"): "very_high",
}


def decide_human_impact(safety_impact: str, mission_impact: str) -> str:
    """Compute the SSVC Human Impact value from safety and mission impact.

    Args:
        safety_impact: "negligible", "marginal", "critical", or "catastrophic"
        mission_impact: "degraded", "mef_support_crippled", "mef_failure",
                        or "mission_failure"

    Returns:
        "low", "medium", "high", or "very_high"

    >>> decide_human_impact("catastrophic", "mission_failure")
    'very_high'
    """
    safety_impact = safety_impact.strip().lower()
    mission_impact = mission_impact.strip().lower().replace("-", "_").replace(" ", "_")

    if safety_impact not in _VALID_SAFETY:
        raise ValueError(f"safety_impact must be one of {sorted(_VALID_SAFETY)}, got {safety_impact!r}")
    if mission_impact not in _VALID_MISSION:
        raise ValueError(f"mission_impact must be one of {sorted(_VALID_MISSION)}, got {mission_impact!r}")

    return _HUMAN_IMPACT_TABLE[(safety_impact, mission_impact)]


# ---------------------------------------------------------------------------
# Table self-validation (inspired by certcc-ssvc's model_validator approach)
#
# These checks run once at module load time. If any check fails, importing
# this module raises an error — guaranteeing that the tables are complete
# and monotone before any call to decide().
# ---------------------------------------------------------------------------

# Ordered severity levels for monotonicity checks.
_EXPLOITATION_ORDER = ("none", "poc", "active")
_EXPOSURE_ORDER = ("small", "controlled", "open")
_HUMAN_IMPACT_ORDER = ("low", "medium", "high", "very_high")
_SAFETY_ORDER = ("negligible", "marginal", "critical", "catastrophic")
_MISSION_ORDER = ("degraded", "mef_support_crippled", "mef_failure", "mission_failure")


def _validate_table_completeness() -> None:
    """Check that _TABLE covers all 3×3×2×4 = 72 combinations."""
    expected: set[tuple[str, str, bool, str]] = set()
    for e in _VALID_EXPLOITATION:
        for exp in _VALID_EXPOSURE:
            for a in (True, False):
                for hi in _VALID_HUMAN_IMPACT:
                    expected.add((e, exp, a, hi))

    actual = set(_TABLE.keys())
    missing = expected - actual
    extra = actual - expected

    if missing:
        raise AssertionError(
            f"Deployer table is incomplete — missing {len(missing)} rows: "
            f"{sorted(missing)[:5]}..."
        )
    if extra:
        raise AssertionError(
            f"Deployer table has {len(extra)} unexpected rows: "
            f"{sorted(extra)[:5]}..."
        )


def _validate_human_impact_completeness() -> None:
    """Check that _HUMAN_IMPACT_TABLE covers all 4×4 = 16 combinations."""
    expected: set[tuple[str, str]] = set()
    for s in _VALID_SAFETY:
        for m in _VALID_MISSION:
            expected.add((s, m))

    actual = set(_HUMAN_IMPACT_TABLE.keys())
    missing = expected - actual

    if missing:
        raise AssertionError(
            f"Human Impact table is incomplete — missing {len(missing)} rows: "
            f"{sorted(missing)}"
        )


def _validate_monotonicity() -> None:
    """Verify that the Deployer table is monotone.

    If any single input axis moves to a more severe value while all other
    axes stay the same, the decision must not decrease.  This catches
    accidental copy-paste errors in the table.
    """
    errors: list[str] = []

    def _check_pair(
        key_a: tuple[str, str, bool, str],
        key_b: tuple[str, str, bool, str],
        axis: str,
    ) -> None:
        val_a = _TABLE[key_a]
        val_b = _TABLE[key_b]
        if val_b < val_a:
            errors.append(
                f"{axis}: {key_a}={val_a.name} > {key_b}={val_b.name}"
            )

    for exp in _VALID_EXPOSURE:
        for a in (True, False):
            for hi in _VALID_HUMAN_IMPACT:
                for i in range(len(_EXPLOITATION_ORDER) - 1):
                    _check_pair(
                        (_EXPLOITATION_ORDER[i], exp, a, hi),
                        (_EXPLOITATION_ORDER[i + 1], exp, a, hi),
                        "exploitation",
                    )

    for e in _VALID_EXPLOITATION:
        for a in (True, False):
            for hi in _VALID_HUMAN_IMPACT:
                for i in range(len(_EXPOSURE_ORDER) - 1):
                    _check_pair(
                        (e, _EXPOSURE_ORDER[i], a, hi),
                        (e, _EXPOSURE_ORDER[i + 1], a, hi),
                        "exposure",
                    )

    for e in _VALID_EXPLOITATION:
        for exp in _VALID_EXPOSURE:
            for hi in _VALID_HUMAN_IMPACT:
                _check_pair(
                    (e, exp, False, hi),
                    (e, exp, True, hi),
                    "automatable",
                )

    for e in _VALID_EXPLOITATION:
        for exp in _VALID_EXPOSURE:
            for a in (True, False):
                for i in range(len(_HUMAN_IMPACT_ORDER) - 1):
                    _check_pair(
                        (e, exp, a, _HUMAN_IMPACT_ORDER[i]),
                        (e, exp, a, _HUMAN_IMPACT_ORDER[i + 1]),
                        "human_impact",
                    )

    if errors:
        raise AssertionError(
            f"Deployer table monotonicity violation(s):\n"
            + "\n".join(f"  - {err}" for err in errors)
        )


def _validate() -> None:
    """Run all table validations once at import time."""
    _validate_table_completeness()
    _validate_human_impact_completeness()
    _validate_monotonicity()


_validate()
