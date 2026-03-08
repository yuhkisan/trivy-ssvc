from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ssvc_calc import Decision as Status
from ssvc_calc import decide, decide_human_impact

from trivy_ssvc.trivy import Vulnerability
from trivy_ssvc.exploit import calc_exploitation, calc_exploitation_fallback


@dataclass
class Params:
    system_exposure: str   # open / controlled / small
    safety_impact: str     # negligible / marginal / critical / catastrophic
    mission_impact: str    # degraded / mef_support_crippled / mef_failure / mission_failure


@dataclass
class Result:
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    exploitation: str   # none / poc / active
    automatable: bool
    human_impact: str   # low / medium / high / very_high
    status: Status

    def key(self) -> str:
        return f"{self.vuln_id}:{self.pkg_name}:{self.installed_version}"


def score_all(
    vulns: list[Vulnerability],
    params: Params,
    kev_ids: Optional[set[str]] = None,
    epss_scores: Optional[dict[str, float]] = None,
) -> list[Result]:
    human_impact = decide_human_impact(params.safety_impact, params.mission_impact)
    results = []
    for v in vulns:
        if kev_ids is not None and epss_scores is not None:
            exploitation = calc_exploitation(v.vuln_id, v.severity, kev_ids, epss_scores)
        else:
            exploitation = calc_exploitation_fallback(v.severity)
        automatable = v.is_automatable()
        status = decide(
            exploitation=exploitation,
            exposure=params.system_exposure,
            automatable=automatable,
            human_impact=human_impact,
        )
        results.append(Result(
            vuln_id=v.vuln_id,
            pkg_name=v.pkg_name,
            installed_version=v.installed_version,
            fixed_version=v.fixed_version,
            severity=v.severity,
            title=v.title,
            exploitation=exploitation,
            automatable=automatable,
            human_impact=human_impact,
            status=status,
        ))
    return results
