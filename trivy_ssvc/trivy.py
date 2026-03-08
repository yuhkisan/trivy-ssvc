from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class CVSSData:
    v3_vector: str = ""
    v3_score: float = 0.0

    @classmethod
    def from_dict(cls, d: dict) -> CVSSData:
        return cls(
            v3_vector=d.get("V3Vector", ""),
            v3_score=d.get("V3Score", 0.0),
        )


@dataclass
class Vulnerability:
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    cvss: dict[str, CVSSData] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> Vulnerability:
        cvss = {
            source: CVSSData.from_dict(data)
            for source, data in (d.get("CVSS") or {}).items()
        }
        return cls(
            vuln_id=d.get("VulnerabilityID", ""),
            pkg_name=d.get("PkgName", ""),
            installed_version=d.get("InstalledVersion", ""),
            fixed_version=d.get("FixedVersion", ""),
            severity=d.get("Severity", ""),
            title=d.get("Title", ""),
            cvss=cvss,
        )

    def key(self) -> str:
        return f"{self.vuln_id}:{self.pkg_name}:{self.installed_version}"

    def v3_vector(self) -> str:
        if "nvd" in self.cvss and self.cvss["nvd"].v3_vector:
            return self.cvss["nvd"].v3_vector
        for data in self.cvss.values():
            if data.v3_vector:
                return data.v3_vector
        return ""

    def is_automatable(self) -> bool:
        """Estimate whether the vulnerability is automatable from CVSS v3 vector.

        A vulnerability is considered automatable when it can be exploited
        over the network (AV:N), with low complexity (AC:L), and without
        requiring any privileges (PR:N).
        """
        vec = self.v3_vector()
        return "AV:N" in vec and "AC:L" in vec and "PR:N" in vec


@dataclass
class Report:
    results: list[dict] = field(default_factory=list)

    def vulnerabilities(self) -> list[Vulnerability]:
        seen: set[str] = set()
        vulns: list[Vulnerability] = []
        for result in self.results:
            for v_dict in result.get("Vulnerabilities") or []:
                v = Vulnerability.from_dict(v_dict)
                if v.key() not in seen:
                    seen.add(v.key())
                    vulns.append(v)
        return vulns


def parse_file(path: str) -> Report:
    with open(path) as f:
        data = json.load(f)
    return Report(results=data.get("Results") or [])
