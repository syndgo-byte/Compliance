"""ops/security 결과 읽기 (GET /findings). compliance 는 security 에 아무것도 보내지 않는다."""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

ACTIVE = ("open", "ready", "delivered")     # delivered: 조치 전달됨, 다음 진단에서 사라져야 해결


class SecurityError(RuntimeError):
    pass


def _get(url: str, timeout: float = 10.0) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


class SecurityClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8200", get=_get):
        self.base = base_url.rstrip("/")
        self._get = get

    def active_findings(self) -> dict[str, list[dict]]:
        """서비스별 미해결 findings. security 가 꺼져 있으면 SecurityError."""
        try:
            rows = json.loads(self._get(f"{self.base}/findings"))
        except Exception as e:
            raise SecurityError(f"security {self.base}/findings 호출 실패: {e}") from e
        out: dict[str, list[dict]] = {}
        for r in rows:
            if r.get("status") in ACTIVE:
                out.setdefault(r["service"], []).append(r)
        return out

    def code_targets(self) -> set[str]:
        """security 가 코드 진단하는 서비스 id (GET /targets 의 code). 여기 없는 서비스는 '보안 미점검'."""
        try:
            data = json.loads(self._get(f"{self.base}/targets"))
        except Exception as e:
            raise SecurityError(f"security {self.base}/targets 호출 실패: {e}") from e
        return set((data.get("code") or {}).keys())
