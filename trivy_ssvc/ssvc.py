from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from trivy_ssvc.trivy import Vulnerability


class Status(IntEnum):
    DEFER = 1
    SCHEDULED = 2
    OUT_OF_CYCLE = 3
    IMMEDIATE = 4

    def __str__(self) -> str:
        return {
            Status.DEFER: "Defer",
            Status.SCHEDULED: "Scheduled",
            Status.OUT_OF_CYCLE: "Out-of-cycle",
            Status.IMMEDIATE: "Immediate",
        }[self]

    @classmethod
    def parse(cls, s: str) -> Status:
        return {
            "immediate": cls.IMMEDIATE,
            "out-of-cycle": cls.OUT_OF_CYCLE,
            "scheduled": cls.SCHEDULED,
            "defer": cls.DEFER,
        }.get(s.lower(), cls.DEFER)


@dataclass
class Params:
    system_exposure: str   # open / controlled / small
    safety_impact: str     # negligible / marginal / critical / catastrophic
    mission_impact: str    # minimal / degraded / failed


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
    human_impact: str   # low / medium / high
    status: Status

    def key(self) -> str:
        return f"{self.vuln_id}:{self.pkg_name}:{self.installed_version}"


def score_all(vulns: list[Vulnerability], params: Params) -> list[Result]:
    human_impact = _calc_human_impact(params.safety_impact, params.mission_impact)
    results = []
    for v in vulns:
        exploitation = _calc_exploitation(v.severity)
        automatable = v.is_automatable()
        status = _decide(exploitation, params.system_exposure, automatable, human_impact)
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


def _calc_exploitation(severity: str) -> str:
    s = severity.upper()
    if s == "CRITICAL":
        return "active"
    if s == "HIGH":
        return "poc"
    return "none"


def _calc_human_impact(safety_impact: str, mission_impact: str) -> str:
    safety = safety_impact.lower()
    mission = mission_impact.lower()

    if safety in ("critical", "catastrophic"):
        return "high"
    if safety == "marginal":
        return "high" if mission == "failed" else "medium"
    # negligible
    if mission == "failed":
        return "high"
    if mission == "degraded":
        return "medium"
    return "low"


def _decide(exploitation: str, exposure: str, automatable: bool, human_impact: str) -> Status:
    expl = exploitation.lower()
    expo = exposure.lower()

    if expl == "none":
        return Status.DEFER

    if expl == "poc":
        if expo == "small":
            return Status.SCHEDULED
        if expo == "controlled":
            if not automatable or human_impact == "low":
                return Status.SCHEDULED
            return Status.OUT_OF_CYCLE
        if expo == "open":
            if not automatable:
                return Status.OUT_OF_CYCLE if human_impact == "high" else Status.SCHEDULED
            if human_impact == "high":
                return Status.IMMEDIATE
            if human_impact == "medium":
                return Status.OUT_OF_CYCLE
            return Status.SCHEDULED

    if expl == "active":
        if expo == "small":
            return Status.OUT_OF_CYCLE
        if expo == "controlled":
            if not automatable:
                return Status.SCHEDULED if human_impact == "low" else Status.OUT_OF_CYCLE
            return Status.IMMEDIATE if human_impact == "high" else Status.OUT_OF_CYCLE
        if expo == "open":
            if not automatable:
                return Status.IMMEDIATE if human_impact == "high" else Status.OUT_OF_CYCLE
            return Status.OUT_OF_CYCLE if human_impact == "low" else Status.IMMEDIATE

    return Status.DEFER
