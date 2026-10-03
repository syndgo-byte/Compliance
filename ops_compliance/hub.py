"""허브와 주고받기: 서비스 목록(누가 privacy.values 를 제공하는지) · 관제판 이벤트 보고.

  서비스 목록: GET /hub/graph → kind=service 노드 → GET /hub/manifest/{id} (provides · source.root)
  이벤트:     POST /monitor/events/{service_id}?event_type=..&severity=..&message=..
http 는 get(url) -> bytes / post(url) -> bytes 로 주입(테스트).
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

CAPABILITY = "privacy.values"
PROFILE_FILE = "privacy_profile.json"     # 서비스 폴더(source.root)에 두는 ServiceProfile
DEFAULT_HUB_URL = os.getenv("MCP_HUB_URL", "http://127.0.0.1:9890")


class HubError(RuntimeError):
    pass


@dataclass
class ServiceInfo:
    id: str
    root: str | None
    provides: list[str] = field(default_factory=list)

    @property
    def connected(self) -> bool:
        return CAPABILITY in self.provides


def _get(url: str, timeout: float = 5.0) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def _post(url: str, timeout: float = 5.0) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, method="POST"), timeout=timeout) as r:
        return r.read()


class HubClient:
    def __init__(self, base_url: str = DEFAULT_HUB_URL, get=_get, post=_post):
        self.base = base_url.rstrip("/")
        self._get, self._post = get, post
        self.last_error: str | None = None

    def _json(self, path: str):
        url = self.base + path
        try:
            return json.loads(self._get(url))
        except Exception as e:
            raise HubError(f"허브 GET {url} 실패: {e}") from e

    def services(self) -> list[ServiceInfo]:
        """웹 서비스(kind=service)만. 모듈 · 관리 서비스는 개인정보 처리자가 아니므로 대상이 아니다."""
        out = []
        for n in self._json("/hub/graph").get("nodes", []):
            if n.get("kind") != "service":
                continue
            m = self._json(f"/hub/manifest/{urllib.parse.quote(n['id'])}")
            out.append(ServiceInfo(n["id"], (m.get("source") or {}).get("root"), list(m.get("provides") or [])))
        return out

    def report(self, service_id: str, event_type: str, severity: str, message: str) -> bool:
        q = urllib.parse.urlencode({"event_type": event_type, "severity": severity, "message": message[:500]})
        url = f"{self.base}/monitor/events/{urllib.parse.quote(service_id)}?{q}"
        try:
            self._post(url)
            self.last_error = None
            return True
        except Exception as e:
            self.last_error = f"허브 POST {self.base}/monitor/events/{service_id} 실패: {e}"
            return False
