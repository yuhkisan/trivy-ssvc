from __future__ import annotations

import json
import sys
from dataclasses import asdict
from typing import IO

from trivy_ssvc.ssvc import Result, Status


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _sorted(results: list[Result]) -> list[Result]:
    return sorted(
        results,
        key=lambda r: (r.status, _SEVERITY_RANK.get(r.severity.upper(), 0)),
        reverse=True,
    )


def table(writer: IO[str], results: list[Result]) -> None:
    headers = ["SSVC", "CVE", "Package", "Version", "Fixed", "Severity", "Title"]
    rows = [
        [
            str(r.status),
            r.vuln_id,
            r.pkg_name,
            r.installed_version,
            r.fixed_version or "-",
            r.severity,
            r.title[:50] if r.title else "-",
        ]
        for r in _sorted(results)
    ]

    col_widths = [max(len(str(v)) for v in [h] + [row[i] for row in rows]) for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)

    writer.write(fmt.format(*headers) + "\n")
    writer.write("  ".join("-" * w for w in col_widths) + "\n")
    for row in rows:
        writer.write(fmt.format(*row) + "\n")


def json_output(writer: IO[str], results: list[Result]) -> None:
    data = [
        {
            "vuln_id": r.vuln_id,
            "pkg_name": r.pkg_name,
            "installed_version": r.installed_version,
            "fixed_version": r.fixed_version,
            "severity": r.severity,
            "title": r.title,
            "exploitation": r.exploitation,
            "automatable": r.automatable,
            "human_impact": r.human_impact,
            "ssvc_status": str(r.status),
        }
        for r in _sorted(results)
    ]
    json.dump(data, writer, indent=2, ensure_ascii=False)
    writer.write("\n")
