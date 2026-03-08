from __future__ import annotations

import json
from urllib import request as urllib_request
from urllib.error import URLError

from trivy_ssvc.ssvc import Status
from trivy_ssvc.state import DiffResult


def slack(webhook_url: str, diff: DiffResult, threshold: Status) -> None:
    lines = []

    for r in diff.added:
        if r.status >= threshold:
            ver = r.installed_version
            fixed = f" → {r.fixed_version}" if r.fixed_version else ""
            lines.append(
                f"[新規] {r.vuln_id} | {r.pkg_name} {ver}{fixed} | {r.status}\n"
                f"対応を検討してください。"
            )

    for e in diff.resolved:
        try:
            resolved_status = Status.parse(e.status)
        except ValueError:
            resolved_status = threshold  # パース失敗時は通知する
        if resolved_status >= threshold:
            lines.append(
                f"[解決] {e.vuln_id} | {e.pkg_name} {e.installed_version}\n"
                f"脆弱性が解消されました。"
            )

    if not lines:
        return

    payload = json.dumps({"text": "\n\n".join(lines)}).encode()
    req = urllib_request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=10):
            pass
    except URLError as e:
        raise RuntimeError(f"Slack通知に失敗しました: {e}") from e
