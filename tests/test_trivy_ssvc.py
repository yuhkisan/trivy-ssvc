"""Tests for bug fixes and logic changes in trivy_ssvc.

Only covers code that had bugs or was modified — not trivial getters/setters.
For SSVC table correctness, see test_decide.py (72 patterns).
"""

from __future__ import annotations

from ssvc_calc import Decision
from trivy_ssvc.trivy import Vulnerability, CVSSData
from trivy_ssvc.exploit import calc_exploitation
from trivy_ssvc.ssvc import Params, Result, score_all
from trivy_ssvc.state import State, Entry, DiffResult, diff


# ---------------------------------------------------------------------------
# Bug fix: diff() should treat all results as "added" on first run
# ---------------------------------------------------------------------------

def test_diff_first_run_all_added():
    """Fixed: diff(None, results) was returning empty DiffResult."""
    r = Result(vuln_id="CVE-1", pkg_name="pkg", installed_version="1.0",
               fixed_version="1.1", severity="HIGH", title="t",
               exploitation="active", automatable=True,
               human_impact="high", status=Decision.IMMEDIATE)
    d = diff(None, [r])
    assert len(d.added) == 1
    assert d.added[0].vuln_id == "CVE-1"


def test_diff_first_run_empty():
    d = diff(None, [])
    assert len(d.added) == 0


# ---------------------------------------------------------------------------
# Bug fix: is_automatable should require PR:N
# ---------------------------------------------------------------------------

def test_is_automatable_requires_pr_n():
    """Fixed: AV:N + AC:L + PR:L should NOT be automatable."""
    v = Vulnerability(
        vuln_id="CVE-1", pkg_name="p", installed_version="1", fixed_version="",
        severity="HIGH", title="",
        cvss={"nvd": CVSSData(v3_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", v3_score=8.8)},
    )
    assert v.is_automatable() is False


def test_is_automatable_all_conditions_met():
    v = Vulnerability(
        vuln_id="CVE-1", pkg_name="p", installed_version="1", fixed_version="",
        severity="HIGH", title="",
        cvss={"nvd": CVSSData(v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", v3_score=9.8)},
    )
    assert v.is_automatable() is True


# ---------------------------------------------------------------------------
# Feature: --epss-threshold propagation
# ---------------------------------------------------------------------------

def test_epss_custom_threshold():
    """epss_threshold should be respected by calc_exploitation."""
    assert calc_exploitation("CVE-1", "LOW", set(), {"CVE-1": 0.3}, epss_threshold=0.5) == "none"
    assert calc_exploitation("CVE-1", "LOW", set(), {"CVE-1": 0.6}, epss_threshold=0.5) == "poc"


def test_score_all_passes_epss_threshold():
    v = Vulnerability(
        vuln_id="CVE-1", pkg_name="pkg", installed_version="1.0",
        fixed_version="1.1", severity="HIGH", title="t",
        cvss={"nvd": CVSSData(v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", v3_score=9.8)},
    )
    params = Params(system_exposure="open", safety_impact="negligible", mission_impact="degraded")
    results = score_all([v], params, kev_ids=set(), epss_scores={"CVE-1": 0.3},
                        epss_threshold=0.5)
    assert results[0].exploitation == "none"  # 0.3 < 0.5 threshold


# ---------------------------------------------------------------------------
# Bug fix: resolved notifications should respect threshold
# ---------------------------------------------------------------------------

def test_resolved_threshold_filter():
    """Fixed: resolved vulns should be filtered by threshold like added ones."""
    from trivy_ssvc.ssvc import Status

    threshold = Decision.SCHEDULED

    # Defer should be filtered out
    entry_defer = Entry(vuln_id="CVE-1", pkg_name="pkg", installed_version="1.0",
                        fixed_version="", severity="LOW", status="Defer",
                        first_seen="2024-01-01T00:00:00")
    assert Status.parse(entry_defer.status) < threshold

    # Immediate should pass
    entry_imm = Entry(vuln_id="CVE-2", pkg_name="pkg", installed_version="1.0",
                      fixed_version="", severity="HIGH", status="Immediate",
                      first_seen="2024-01-01T00:00:00")
    assert Status.parse(entry_imm.status) >= threshold
