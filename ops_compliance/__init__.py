"""ops_compliance — 개인정보 · 컴플라이언스. 법령 개정 감시 결과를 각 서비스에 적용하고, 서비스별 개인정보처리방침이 빠짐없이 채워졌는지 점검.

관리 서비스(ops): 웹 서비스가 가져다 쓰는 모듈이 아니라, 모든 서비스를 위에서 내려다보며 모아서 운영한다.
허브는 kind="ops" 인 서비스를 노드 캔버스에서 MCP Hub 위 줄에, 3D 관제판에서는 하늘에 띄운다.
각 웹 서비스가 `privacy.values` capability 를 제공하면 여기서 수집한다 (필수 아님 — 제공한 서비스만).
"""
from pathlib import Path

__version__ = "0.0.1"
ROOT = Path(__file__).resolve().parent.parent


def manifest() -> dict:
    return {
        "id": "compliance",
        "kind": "ops",
        "version": __version__,
        "description": "법령 개정 감시 결과를 각 서비스에 적용하고, 서비스별 개인정보처리방침이 빠짐없이 채워졌는지 점검",
        "provides": ["ops.compliance"],
        "requires": [],
        "tools": [
            {"name": "ops_compliance.check_policies", "description": "서비스별 처리방침 필수 항목 누락 점검 (위탁 · 보호책임자 · 쿠키 등)", "auth_required": "user", "billing_model": "free"},
            {"name": "ops_compliance.law_changes", "description": "법령 개정 감시 결과와 서비스별 영향", "auth_required": "user", "billing_model": "free"},
            {"name": "ops_compliance.rollout", "description": "승인된 문구 개정을 서비스에 배포 (버전 올림 → 재동의)", "auth_required": "user", "billing_model": "free"},
        ],
        "license": {
            "service_id": "compliance", "environment": "dev", "status": "active",
            "issued_at": "2026-09-29T00:00:00+00:00", "issued_by": "mcp_hub",
        },
        "source": {"root": str(ROOT), "entry": "ops_compliance/__init__.py"},
    }
