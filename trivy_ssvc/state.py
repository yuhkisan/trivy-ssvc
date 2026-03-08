from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from trivy_ssvc.ssvc import Result, Status


@dataclass
class Entry:
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    severity: str
    status: str
    first_seen: str  # ISO 8601


@dataclass
class State:
    entries: dict[str, Entry] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"entries": {k: asdict(v) for k, v in self.entries.items()}}

    @classmethod
    def from_dict(cls, d: dict) -> State:
        entries = {
            k: Entry(**v)
            for k, v in (d.get("entries") or {}).items()
        }
        return cls(entries=entries)


@dataclass
class DiffResult:
    added: list[Result] = field(default_factory=list)
    resolved: list[Entry] = field(default_factory=list)


def from_results(results: list[Result], prev: Optional[State]) -> State:
    now = datetime.now(timezone.utc).isoformat()
    entries: dict[str, Entry] = {}
    for r in results:
        first_seen = now
        if prev and r.key() in prev.entries:
            first_seen = prev.entries[r.key()].first_seen
        entries[r.key()] = Entry(
            vuln_id=r.vuln_id,
            pkg_name=r.pkg_name,
            installed_version=r.installed_version,
            fixed_version=r.fixed_version,
            severity=r.severity,
            status=str(r.status),
            first_seen=first_seen,
        )
    return State(entries=entries)


def load_file(path: str) -> Optional[State]:
    try:
        with open(path) as f:
            return State.from_dict(json.load(f))
    except FileNotFoundError:
        return None


def save_file(path: str, state: State) -> None:
    with open(path, "w") as f:
        json.dump(state.to_dict(), f, indent=2, ensure_ascii=False)


def diff(prev: Optional[State], current: list[Result]) -> DiffResult:
    if prev is None:
        # 初回実行: 全件を「新規」として扱う。
        # 通知するかどうかは --slack-webhook の有無でユーザーが制御する。
        return DiffResult(added=list(current))

    current_keys = {r.key() for r in current}
    added = [r for r in current if r.key() not in prev.entries]
    resolved = [e for k, e in prev.entries.items() if k not in current_keys]
    return DiffResult(added=added, resolved=resolved)
