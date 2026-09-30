"""ops/security 결과 읽기. compliance 는 security 에 판정 결과를 보내지 않는다.

  SecurityCLI (기본) — security 를 상주시키지 않는다. 한 바퀴마다 `python -m security scan` 을 돌리고
                       (끝나면 종료) `list --json` · `targets` 로 결과를 읽는다. 사람이 security 를 안 켜도 12시간마다 진단된다.
  SecurityClient     — security API(serve) 가 떠 있을 때 HTTP 로 읽기.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
import urllib.parse
import urllib.request

SECURITY_HOME = Path(os.getenv("OPS_SECURITY_HOME", r"D:\Vibe_coding\ops\security"))
ACTIVE = ("open", "ready", "delivered")     # delivered: 조치 전달됨, 다음 진단에서 사라져야 해결


class SecurityError(RuntimeError):
    pass


def _get(url: str, timeout: float = 10.0) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def _active(rows) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for r in rows:
        if r.get("status") in ACTIVE:
            out.setdefault(r["service"], []).append(r)
    return out


class SecurityCLI:
    def __init__(self, home: Path = SECURITY_HOME, run=subprocess.run, scan: bool = True, timeout: int = 1800):
        self.home, self._run, self.scan, self.timeout = Path(home), run, scan, timeout
        self.scan_error = None
        self._scanned = False

    def _call(self, *args) -> str:
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        try:
            r = self._run([sys.executable, "-m", "security", *args], cwd=str(self.home), env=env,
                          capture_output=True, text=True, encoding="utf-8", timeout=self.timeout)
        except Exception as e:
            raise SecurityError(f"security {args[0]} 실행 실패: {e}") from e
        if r.returncode != 0:
            raise SecurityError(f"security {args[0]} 실패(코드 {r.returncode}): {(r.stderr or r.stdout)[-300:]}")
        return r.stdout

    def _ensure_scan(self):
        if self.scan and not self._scanned:
            self._scanned = True
            try:
                self._call("scan")
            except SecurityError as e:     # 진단이 실패해도 지난 결과로 판정은 한다(오류는 보고서에)
                self.scan_error = str(e)

    def active_findings(self) -> dict[str, list[dict]]:
        self._ensure_scan()
        try:
            return _active(json.loads(self._call("list", "--json")))
        except json.JSONDecodeError as e:
            raise SecurityError(f"security list --json 출력 해석 실패: {e}") from e

    def code_targets(self) -> set[str]:
        try:
            return set((json.loads(self._call("targets")).get("code") or {}).keys())
        except json.JSONDecodeError as e:
            raise SecurityError(f"security targets 출력 해석 실패: {e}") from e


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
        return _active(rows)

    def code_targets(self) -> set[str]:
        """security 가 코드 진단하는 서비스 id (GET /targets 의 code). 여기 없는 서비스는 '보안 미점검'."""
        try:
            data = json.loads(self._get(f"{self.base}/targets"))
        except Exception as e:
            raise SecurityError(f"security {self.base}/targets 호출 실패: {e}") from e
        return set((data.get("code") or {}).keys())
