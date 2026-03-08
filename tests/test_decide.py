"""Test ssvc_calc.decide against the CERT/CC SSVC v2 Deployer decision table.

The 72 test cases below are taken directly from the certcc-ssvc package
(DEPLOYER_1 mapping table). Every valid input combination is covered.
"""

import pytest

from ssvc_calc import Decision, decide, decide_human_impact


# -- Key mapping from certcc-ssvc short codes to ssvc-calc values -----------
_EXPLOITATION = {"N": "none", "P": "poc", "A": "active"}
_EXPOSURE = {"S": "small", "C": "controlled", "O": "open"}
_AUTOMATABLE = {"N": False, "Y": True}
_HUMAN_IMPACT = {"L": "low", "M": "medium", "H": "high", "VH": "very_high"}
_DECISION = {"D": Decision.DEFER, "S": Decision.SCHEDULED, "O": Decision.OUT_OF_CYCLE, "I": Decision.IMMEDIATE}

# -- All 72 rows from CERT/CC DEPLOYER_1 -----------------------------------
# (exploitation, exposure, automatable, human_impact, expected_decision)
DEPLOYER_TABLE = [
    # exploitation=none, exposure=small
    ("N", "S", "N", "L", "D"),
    ("N", "S", "N", "M", "D"),
    ("N", "S", "N", "H", "S"),
    ("N", "S", "N", "VH", "S"),
    ("N", "S", "Y", "L", "D"),
    ("N", "S", "Y", "M", "S"),
    ("N", "S", "Y", "H", "S"),
    ("N", "S", "Y", "VH", "S"),
    # exploitation=none, exposure=controlled
    ("N", "C", "N", "L", "D"),
    ("N", "C", "N", "M", "S"),
    ("N", "C", "N", "H", "S"),
    ("N", "C", "N", "VH", "S"),
    ("N", "C", "Y", "L", "S"),
    ("N", "C", "Y", "M", "S"),
    ("N", "C", "Y", "H", "S"),
    ("N", "C", "Y", "VH", "S"),
    # exploitation=none, exposure=open
    ("N", "O", "N", "L", "D"),
    ("N", "O", "N", "M", "S"),
    ("N", "O", "N", "H", "S"),
    ("N", "O", "N", "VH", "S"),
    ("N", "O", "Y", "L", "S"),
    ("N", "O", "Y", "M", "S"),
    ("N", "O", "Y", "H", "S"),
    ("N", "O", "Y", "VH", "O"),
    # exploitation=poc, exposure=small
    ("P", "S", "N", "L", "D"),
    ("P", "S", "N", "M", "S"),
    ("P", "S", "N", "H", "S"),
    ("P", "S", "N", "VH", "S"),
    ("P", "S", "Y", "L", "S"),
    ("P", "S", "Y", "M", "S"),
    ("P", "S", "Y", "H", "S"),
    ("P", "S", "Y", "VH", "S"),
    # exploitation=poc, exposure=controlled
    ("P", "C", "N", "L", "D"),
    ("P", "C", "N", "M", "S"),
    ("P", "C", "N", "H", "S"),
    ("P", "C", "N", "VH", "S"),
    ("P", "C", "Y", "L", "S"),
    ("P", "C", "Y", "M", "S"),
    ("P", "C", "Y", "H", "S"),
    ("P", "C", "Y", "VH", "O"),
    # exploitation=poc, exposure=open
    ("P", "O", "N", "L", "S"),
    ("P", "O", "N", "M", "S"),
    ("P", "O", "N", "H", "S"),
    ("P", "O", "N", "VH", "O"),
    ("P", "O", "Y", "L", "S"),
    ("P", "O", "Y", "M", "S"),
    ("P", "O", "Y", "H", "O"),
    ("P", "O", "Y", "VH", "O"),
    # exploitation=active, exposure=small
    ("A", "S", "N", "L", "S"),
    ("A", "S", "N", "M", "S"),
    ("A", "S", "N", "H", "O"),
    ("A", "S", "N", "VH", "O"),
    ("A", "S", "Y", "L", "S"),
    ("A", "S", "Y", "M", "O"),
    ("A", "S", "Y", "H", "O"),
    ("A", "S", "Y", "VH", "O"),
    # exploitation=active, exposure=controlled
    ("A", "C", "N", "L", "S"),
    ("A", "C", "N", "M", "S"),
    ("A", "C", "N", "H", "O"),
    ("A", "C", "N", "VH", "O"),
    ("A", "C", "Y", "L", "O"),
    ("A", "C", "Y", "M", "O"),
    ("A", "C", "Y", "H", "O"),
    ("A", "C", "Y", "VH", "O"),
    # exploitation=active, exposure=open
    ("A", "O", "N", "L", "S"),
    ("A", "O", "N", "M", "O"),
    ("A", "O", "N", "H", "O"),
    ("A", "O", "N", "VH", "I"),
    ("A", "O", "Y", "L", "O"),
    ("A", "O", "Y", "M", "O"),
    ("A", "O", "Y", "H", "I"),
    ("A", "O", "Y", "VH", "I"),
]


@pytest.mark.parametrize(
    "e, exp, a, hi, expected",
    DEPLOYER_TABLE,
    ids=[
        f"{e}-{exp}-{'auto' if a == 'Y' else 'noauto'}-{hi}"
        for e, exp, a, hi, _ in DEPLOYER_TABLE
    ],
)
def test_deployer_table(e, exp, a, hi, expected):
    result = decide(
        exploitation=_EXPLOITATION[e],
        exposure=_EXPOSURE[exp],
        automatable=_AUTOMATABLE[a],
        human_impact=_HUMAN_IMPACT[hi],
    )
    assert result == _DECISION[expected]


def test_table_completeness():
    """Ensure the table covers all 72 combinations."""
    assert len(DEPLOYER_TABLE) == 72


# -- Decision.parse tests --------------------------------------------------

@pytest.mark.parametrize("label,expected", [
    ("Defer", Decision.DEFER),
    ("Scheduled", Decision.SCHEDULED),
    ("Out-of-cycle", Decision.OUT_OF_CYCLE),
    ("Immediate", Decision.IMMEDIATE),
    ("  immediate  ", Decision.IMMEDIATE),
    ("OUT_OF_CYCLE", Decision.OUT_OF_CYCLE),
])
def test_decision_parse(label, expected):
    assert Decision.parse(label) == expected


def test_decision_parse_invalid():
    with pytest.raises(ValueError):
        Decision.parse("invalid")


# -- Decision.__str__ tests ------------------------------------------------

def test_decision_str():
    assert str(Decision.DEFER) == "Defer"
    assert str(Decision.SCHEDULED) == "Scheduled"
    assert str(Decision.OUT_OF_CYCLE) == "Out-of-cycle"
    assert str(Decision.IMMEDIATE) == "Immediate"


# -- decide validation tests ------------------------------------------------

def test_decide_invalid_exploitation():
    with pytest.raises(ValueError, match="exploitation"):
        decide("bad", "open", True, "high")


def test_decide_invalid_exposure():
    with pytest.raises(ValueError, match="exposure"):
        decide("none", "bad", True, "high")


def test_decide_invalid_human_impact():
    with pytest.raises(ValueError, match="human_impact"):
        decide("none", "open", True, "bad")


# -- decide_human_impact tests ---------------------------------------------

@pytest.mark.parametrize("safety,mission,expected", [
    # negligible safety
    ("negligible", "degraded", "low"),
    ("negligible", "mef_support_crippled", "low"),
    ("negligible", "mef_failure", "medium"),
    ("negligible", "mission_failure", "very_high"),
    # marginal safety
    ("marginal", "degraded", "low"),
    ("marginal", "mef_support_crippled", "low"),
    ("marginal", "mef_failure", "medium"),
    ("marginal", "mission_failure", "very_high"),
    # critical safety
    ("critical", "degraded", "medium"),
    ("critical", "mef_support_crippled", "high"),
    ("critical", "mef_failure", "high"),
    ("critical", "mission_failure", "very_high"),
    # catastrophic safety
    ("catastrophic", "degraded", "very_high"),
    ("catastrophic", "mef_support_crippled", "very_high"),
    ("catastrophic", "mef_failure", "very_high"),
    ("catastrophic", "mission_failure", "very_high"),
])
def test_decide_human_impact(safety, mission, expected):
    assert decide_human_impact(safety, mission) == expected


def test_decide_human_impact_completeness():
    """Ensure human impact table covers all 16 combinations."""
    count = 0
    for safety in ("negligible", "marginal", "critical", "catastrophic"):
        for mission in ("degraded", "mef_support_crippled", "mef_failure", "mission_failure"):
            decide_human_impact(safety, mission)
            count += 1
    assert count == 16


def test_decide_human_impact_invalid_safety():
    with pytest.raises(ValueError, match="safety_impact"):
        decide_human_impact("bad", "degraded")


def test_decide_human_impact_invalid_mission():
    with pytest.raises(ValueError, match="mission_impact"):
        decide_human_impact("negligible", "bad")
