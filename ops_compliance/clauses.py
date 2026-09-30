"""법령 조항 ↔ ops/security 규칙 ID 매핑.

조항 본문은 법제처 행정규칙 API 에서 받은 현행본이다 (2026-09-30 조회).
  · 개인정보의 안전성 확보조치 기준 (개인정보보호위원회 고시, 2026-07-01 시행, 일련번호 2100000281400)
  · 정보보호조치에 관한 지침 (과기정통부 고시, 2017-08-24 시행, 2100000095222) — 세부 조치는 [별표 1] HWP 첨부
  · 전자금융감독규정 (금융위원회 고시, 2026-07-15 시행, 2100000282622) — 금융회사 · 전자금융업자에만 적용
규칙 ID 는 ops/security/security/scanners 에서 실제로 내는 것만 쓴다(tests 에서 scanners 소스와 대조).

이 표는 '법적 해석'이라 security 쪽이 아니라 여기(준수 판정 쪽)에 둔다.
규칙이 안 걸렸다는 것은 "알려진 위반 신호 없음"이지 조항을 충족한다는 증명이 아니다.
조직 · 절차 · 물리 조치(내부 관리계획, 교육, 출입통제, 백업 절차 등)는 코드로 볼 수 없어 표에 없다.
"""
from __future__ import annotations

SAFETY = "개인정보의 안전성 확보조치 기준"
ICT = "정보보호조치에 관한 지침"
EFIN = "전자금융감독규정"

# applies: 누구에게 적용되나. "all" 은 모든 서비스, 그 외는 scope.json 에 서비스별로 켜야 평가한다.
LAWS = {
    SAFETY: {"applies": "all", "basis": "개인정보처리자 전부 (개인정보 보호법 제29조)"},
    ICT: {"applies": "all", "basis": "정보통신서비스 제공자 (정보통신망법 제45조③) — 웹 서비스는 해당"},
    EFIN: {"applies": "opt-in", "basis": "금융회사 · 전자금융업자만. PG 결제창만 붙인 가맹점은 대상 아님"},
}

CLAUSES: list[dict] = [
    # ── 개인정보의 안전성 확보조치 기준
    {"law": SAFETY, "article": "제6조①1호", "title": "접속 권한을 IP 등으로 제한",
     "rules": ["HARD-BIND-ALL", "HARD-HOST-NET", "HARD-PORT-PUBLIC"]},
    {"law": SAFETY, "article": "제6조②", "title": "외부 접속 시 안전한 인증수단(OTP·보안토큰 등)",
     "rules": ["LEGAL-NO-MFA"]},
    {"law": SAFETY, "article": "제6조③", "title": "인터넷 홈페이지 등으로 권한 없는 자에게 공개·유출되지 않게 조치",
     "rules": ["WEB-EXPOSED-ENV", "WEB-EXPOSED-GIT", "WEB-EXPOSED-OPENAPI", "SECRET-ENV-TRACKED",
               "SECRET-ENV-NOT-IGNORED", "CONFIG-CORS-WILDCARD", "WEB-CORS-CRED", "WEB-CORS-REFLECT"]},
    {"law": SAFETY, "article": "제6조④", "title": "일정 시간 미사용 시 자동 접속 차단",
     "rules": ["LEGAL-SESSION-NO-EXPIRY", "LEGAL-SESSION-LONG"]},
    {"law": SAFETY, "article": "제7조①", "title": "비밀번호 등 인증정보의 안전한 암호화(비밀번호는 일방향)",
     "rules": ["SAST-PY-WEAK-HASH", "LEGAL-PASSWORD-PLAIN", "LEGAL-PASSWORD-FAST-HASH"]},
    {"law": SAFETY, "article": "제7조②", "title": "주민등록번호 등 고유식별정보·카드·계좌번호 암호화 저장",
     "rules": ["PIPA-UNIQUE-ID-PLAINTEXT"]},
    {"law": SAFETY, "article": "제7조④", "title": "인터넷망 구간 송·수신 시 암호화",
     "rules": ["WEB-NO-HTTPS", "WEB-TLS-INVALID", "WEB-TLS-EXPIRY", "WEB-HDR-HSTS", "SAST-PY-TLS-VERIFY",
               "CONFIG-COOKIE-FLAGS", "WEB-COOKIE"]},
    {"law": SAFETY, "article": "제8조①", "title": "접속기록 1년(해당 시 2년) 이상 보관",
     "rules": ["LEGAL-LOG-NO-ACCESS-LOG", "LEGAL-LOG-RETENTION"]},
    {"law": SAFETY, "article": "제9조", "title": "악성프로그램 방지·보안 업데이트 즉시 적용(의존성 범위만 확인 가능)",
     "rules": ["DEPS-CVE", "DEPS-CVE-FLOOR", "DEPS-UNPINNED"]},

    # ── 정보보호조치에 관한 지침 [별표 1] 기술적 보호조치
    {"law": ICT, "article": "별표1 2.2.4", "title": "DB서버는 외부망에서 직접 접속할 수 없게",
     "rules": ["HARD-PORT-PUBLIC", "HARD-BIND-ALL", "HARD-HOST-NET"]},
    {"law": ICT, "article": "별표1 2.2.7", "title": "취약점 점검·보완 (연 1회 이상)",
     "rules": ["SAST-PY-SQLI", "SAST-PY-SQL-DYNAMIC", "SAST-PY-SQL-DDL", "SAST-PY-SHELL", "SAST-PY-EVAL",
               "SAST-PY-PICKLE", "SAST-PY-YAML", "SAST-PY-MKTEMP", "SAST-JS-EVAL", "SAST-JS-INNERHTML",
               "SAST-JS-DANGEROUS-HTML", "SAST-JS-DOCWRITE", "WEB-HDR-CSP", "WEB-HDR-FRAME", "WEB-HDR-NOSNIFF"]},
    {"law": ICT, "article": "별표1 2.2.8", "title": "인가된 자만 접속·외부 접속 시 일회용 패스워드, 불필요 서비스 제거",
     "rules": ["LEGAL-NO-MFA", "CONFIG-DEBUG", "CONFIG-DEBUG-RUN", "WEB-EXPOSED-OPENAPI", "WEB-HDR-VERSION",
               "HARD-PRIVILEGED", "HARD-CAP-ADD", "HARD-DOCKER-ROOT", "HARD-SYSTEMD-ROOT", "HARD-SYSTEMD-SANDBOX",
               "HARD-NO-NEW-PRIV", "HARD-RAW-SOCKET"]},
    {"law": ICT, "article": "별표1 2.2.9", "title": "관리자 비밀번호 8자리 이상",
     "rules": ["LEGAL-PASSWORD-MINLEN"]},
    {"law": ICT, "article": "별표1 2.2.10", "title": "로그기록 최소 1개월 이상 유지",
     "rules": ["LEGAL-LOG-NO-ACCESS-LOG"]},
    {"law": ICT, "article": "별표1 2.2.11", "title": "보안패치 주기적 입수·적용",
     "rules": ["DEPS-CVE", "DEPS-CVE-FLOOR", "DEPS-UNPINNED"]},
    {"law": ICT, "article": "별표1 2.2.13", "title": "비밀번호 일방향 암호화, 주민번호·카드·계좌번호 암호화 저장",
     "rules": ["LEGAL-PASSWORD-PLAIN", "LEGAL-PASSWORD-FAST-HASH", "SAST-PY-WEAK-HASH", "PIPA-UNIQUE-ID-PLAINTEXT"]},
    {"law": ICT, "article": "별표1 2.2.8 (비밀정보)", "title": "인가된 자만 접속 — 키·토큰이 코드에 노출되면 인가 통제가 무력화",
     "rules": ["SECRET-HARDCODED", "SECRET-AI-KEY", "SECRET-AWS-KEY", "SECRET-GITHUB-TOKEN", "SECRET-GOOGLE-KEY",
               "SECRET-PRIVATE-KEY", "SECRET-SLACK-TOKEN", "CONFIG-LOG-SECRET"]},

    # ── 전자금융감독규정 (opt-in)
    {"law": EFIN, "article": "제13조①9호", "title": "정보처리시스템 가동기록 자동 기록·1년 이상 보존",
     "rules": ["LEGAL-LOG-NO-ACCESS-LOG", "LEGAL-LOG-RETENTION"]},
    {"law": EFIN, "article": "제15조①2호", "title": "긴급·중요 보정(patch) 즉시 적용",
     "rules": ["DEPS-CVE", "DEPS-CVE-FLOOR"]},
    {"law": EFIN, "article": "제17조", "title": "공개용 웹서버: 이중 인증, 시험·개발 도구 제한, 고유식별정보 암호화",
     "rules": ["LEGAL-NO-MFA", "CONFIG-DEBUG", "CONFIG-DEBUG-RUN", "WEB-EXPOSED-OPENAPI", "PIPA-UNIQUE-ID-PLAINTEXT"]},
    {"law": EFIN, "article": "제19조②", "title": "암호·인증시스템 키의 안전한 관리",
     "rules": ["SECRET-HARDCODED", "SECRET-PRIVATE-KEY", "SECRET-AI-KEY", "SECRET-AWS-KEY", "SECRET-GOOGLE-KEY"]},
    {"law": EFIN, "article": "제34조의3①", "title": "이용자 비밀번호 암호화·조회 불가",
     "rules": ["LEGAL-PASSWORD-PLAIN", "LEGAL-PASSWORD-FAST-HASH", "SAST-PY-WEAK-HASH"]},
    {"law": EFIN, "article": "제34조의3②1·2호", "title": "유추 어려운 비밀번호 규칙, 입력 오류 횟수 초과 시 즉시 중지",
     "rules": ["LEGAL-PASSWORD-MINLEN", "LEGAL-NO-LOGIN-LOCKOUT"]},
]

_SEV = ["critical", "high", "medium", "low"]
_KEYS = ("id", "rule", "severity", "title", "file", "line")


def laws_for(opted: list[str] | None) -> list[str]:
    """이 서비스에 평가할 법령. applies=all 은 항상, opt-in 은 scope 에 있을 때만."""
    opted = set(opted or [])
    return [name for name, m in LAWS.items() if m["applies"] == "all" or name in opted]


def evaluate(findings: list[dict], opted: list[str] | None = None) -> dict:
    """한 서비스의 열린 security findings → 조항별 결과 + 어느 조항에도 안 붙은 규칙.

    status: '미흡'(규칙에 걸린 항목 있음) | '신호 없음'(알려진 위반 신호 없음 — 충족 증명 아님)
    한 규칙이 여러 법령 조항에 걸릴 수 있다(예: 비밀번호 해시 → 안전성 기준 제7조① · 지침 2.2.13).
    """
    laws = laws_for(opted)
    active = [c for c in CLAUSES if c["law"] in laws]
    mapped = {r for c in CLAUSES for r in c["rules"]}
    clauses = []
    for c in active:
        items = [f for f in findings if f["rule"] in c["rules"]]
        clauses.append({"law": c["law"], "article": c["article"], "title": c["title"],
                        "status": "미흡" if items else "신호 없음", "count": len(items),
                        "worst": min((i["severity"] for i in items), key=_SEV.index, default=None),
                        "findings": [{k: i.get(k) for k in _KEYS} for i in items]})
    return {"laws": laws,
            "skipped": {n: LAWS[n]["basis"] for n in LAWS if n not in laws},
            "clauses": clauses,
            "unmapped": [{k: f.get(k) for k in _KEYS} for f in findings if f["rule"] not in mapped]}
