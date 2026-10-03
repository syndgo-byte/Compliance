"""한 바퀴: 서비스 수집 → Privacy_Law 감시(법령 · 개인정보위 · 처리방침) + 서비스별 점검 → 보고서 · 알림.

  1. 허브에서 웹 서비스 목록. privacy.values 를 제공하는 서비스는 폴더의 privacy_profile.json(ServiceProfile)을 읽는다.
     제공하지 않으면 '미연결', 제공하는데 프로필이 없거나 틀리면 '프로필 오류'.
  2. privacy_law.watch.run(profiles=...) — 법령 개정 · 매핑 · 규칙 근거 · 문구 점검 · 처분 사례 · 처리방침 비교.
  3. 서비스별 결과(점검 오류 · 처분 사례 공백 · 벤치마크 공백 · 전용 문서 여부)로 정리해 reports/latest.json.
  4. 허브 관제판 알림은 지난 바퀴에 없던 것만 보낸다(12시간마다 같은 경고가 반복되지 않게).
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .clauses import evaluate
from .hub import PROFILE_FILE, HubClient, HubError, ServiceInfo
from .security import SecurityCLI, SecurityClient, SecurityError

HOME = Path(__file__).resolve().parent.parent
SELF = "compliance"          # 허브에 등록된 이 관리 서비스의 id
ONE_SHOT = ("law:", "notice:", "policy:")     # 감시가 한 번만 알려 주는 이벤트


def load_profile(svc: ServiceInfo):
    """(ServiceProfile | None, 상태, 설명)"""
    from privacy_law.profile import ServiceProfile
    if not svc.connected:
        return None, "미연결", "privacy.values 를 제공하지 않음 — 서비스 manifest provides 에 추가하고 privacy_profile.json 작성"
    if not svc.root:
        return None, "프로필 오류", "허브에 서비스 폴더(source.root)가 없음"
    p = Path(svc.root) / PROFILE_FILE
    if not p.exists():
        return None, "프로필 오류", f"{p} 없음"
    try:
        prof = ServiceProfile.load(p)
    except (ValueError, KeyError, OSError) as e:
        return None, "프로필 오류", f"{p}: {e}"
    if prof.service != svc.id:
        return None, "프로필 오류", f"{p}: service 가 '{prof.service}' — 허브 id '{svc.id}' 와 같아야 함"
    return prof, "연결", str(p)


def load_scope(home: Path = HOME) -> dict[str, dict[str, bool]]:
    """scope.json: 서비스별 특징 기반 법령 선택. 예: {"EMSv3": {"판매": true, "직접결제": true, ...}}

    반환: {서비스ID: {특징: true/false, ...}} 형태. 특징 → laws_for() 가 법령 자동 선택.
    """
    p = Path(home) / "scope.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    # 형식 확인: list(옛 형식)면 경고
    for sid, v in data.items():
        if isinstance(v, list):
            raise ValueError(f"{sid}: scope.json 형식이 옛 버전입니다. 특징 기반으로 변경 필요: "
                           "{\"판매\": true/false, \"위치\": ..., \"직접결제\": ..., \"공공\": ...}")
    return data


def _alerts(report: dict) -> list[dict]:
    """보고서 → 알림 후보. key 가 같으면 같은 알림(지난 바퀴와 비교용)."""
    out = []

    def add(key, service, event_type, severity, message):
        out.append({"key": key, "service": service, "event_type": event_type, "severity": severity, "message": message})

    law = report["law"]
    for ch in law["changed"]:
        n = len(ch["proposals"])
        arts = ", ".join(f"제{a}조" for a in ch["articles"][:8])
        add(f"law:{ch['law']}:{ch['mst']}", SELF, "law_change", "high" if n else "low",
            f"{ch['law']} 개정(시행 {ch['effective']}): {arts}" + (f" → 수정 제안 {n}건 검토 대기" if n else " → 동의 문서 영향 없음"))
    for m in law["mapping_issues"]:
        add(f"map:{m['law']}:{m['article']}:{m['actual']}", SELF, "change", "medium", m["message"])
    for s in law["stale_rules"]:
        add(f"stale:{s['rule']}:{s['reason']}", SELF, "change", "high",
            f"점검 규칙 {s['rule']} 근거({s['law']} 제{s['article']}조) {s['reason']} — 규칙 검토 후 rebase")
    for n in law["notices"]:
        if n["topics"]:
            add(f"notice:{n['board']}:{n['ntt_id']}", SELF, "change", "low",
                f"개인정보위 {n['board']}: {n['title']} ({', '.join(n['topics'])}) {n['url']}")
    for d in law["manual_review"]:
        add(f"manual:{d['ntt_id']}", SELF, "change", "low",
            f"처분 공표 {d['date']} 첨부를 읽지 못함({', '.join(d['unparsed'])}) — 직접 확인 {d['url']}")
    for c in law["policy_changes"]:
        add(f"policy:{c['name']}:{c['to']}", SELF, "change", "low",
            f"{c['name']} 처리방침 변경({c['from']} → {c['to']})"
            + (f", 새 주제: {', '.join(c['topics_added'])}" if c["topics_added"] else ""))
    for e in law["errors"]:
        add(f"err:{e[:120]}", SELF, "error", "medium", f"감시 실패: {e}")

    for sid, s in report["services"].items():
        if (s.get("security") or {}).get("untracked"):
            add(f"svc:{sid}:sec:untracked", sid, "compliance", "low",
                f"보안 미점검: {s['security']['detail']} (서비스 폴더 {s['root']})")
        for c in (s.get("security") or {}).get("clauses", []):
            if c["status"] == "미흡":
                add(f"svc:{sid}:sec:{c['law']}:{c['article']}", sid, "compliance",
                    "high" if c["worst"] in ("critical", "high") else "medium",
                    f"{c['law']} {c['article']}({c['title']}) 미흡 {c['count']}건: "
                    + ", ".join(sorted({f['rule'] for f in c['findings']}))[:300])
        if s["status"] == "미연결":
            add(f"svc:{sid}:unlinked", sid, "compliance", "low", f"개인정보 점검 미연결: {s['detail']}")
            continue
        if s["status"] == "프로필 오류":
            add(f"svc:{sid}:profile:{s['detail'][:80]}", sid, "compliance", "medium", f"개인정보 프로필 오류: {s['detail']}")
            continue
        for f in s["findings"]:
            if f["severity"] == "error":
                add(f"svc:{sid}:rule:{f['rule']}:{f['doc']}", sid, "compliance", "high", f"개인정보 문구 위반 소지: {f['message']}")
        for g in s["case_gaps"]:
            add(f"svc:{sid}:case:{g['article']}", sid, "compliance", "medium", g["message"])
        for g in s["benchmark_gaps"]:
            if g["action"] == "기재 필요":
                add(f"svc:{sid}:bench:{g['topic']}", sid, "compliance", "medium",
                    f"처리방침에 '{g['topic']}' 기재 필요 (다른 {g['sites']}곳 처리방침에 있고 이 서비스에 해당)")
    return out


def run_cycle(*, hub: HubClient | None = None, services: list[ServiceInfo] | None = None, watch=None,
              security: SecurityClient | None = None, home: Path = HOME, notify: bool = True) -> dict:
    """services 를 주면 허브 목록 대신 사용. watch 는 privacy_law.watch.run 대체(테스트).
    security 는 ops/security 결과 읽기(기본 SecurityCLI: 이번 바퀴에 진단을 직접 돌림). 실패하면 보안 항목만 '결과 없음'."""
    home = Path(home)
    hub = hub or HubClient()
    security = security or SecurityCLI()
    warnings = []
    if services is None:
        try:
            services = hub.services()
        except HubError as e:
            warnings.append(str(e))
            services = []
    if watch is None:
        from privacy_law.watch import run as watch

    loaded = {s.id: load_profile(s) for s in services}
    profiles = [p for p, _, _ in loaded.values() if p]
    try:
        law = watch(profiles=profiles)
    except Exception as e:     # 감시가 죽어도 서비스 목록 · 상태는 남긴다
        law = {"errors": [f"Privacy_Law 감시 실행 오류: {e}"]}
    for k in ("checked", "changed", "errors", "mapping_issues", "stale_rules", "notices", "manual_review",
              "policy_changes", "benchmarks"):
        law.setdefault(k, [])
    for k in ("findings", "case_gaps", "benchmark_gaps", "violations"):
        law.setdefault(k, {})

    try:
        scope = load_scope(home)
    except ValueError as e:       # JSONDecodeError 포함 — 잘못된 scope 는 opt-in 법령만 빼고 계속
        scope = {}
        law["errors"].append(f"scope.json 오류: {e}")
    try:
        sec, sec_err = security.active_findings(), None
        sec_targets = security.code_targets()
        if getattr(security, "scan_error", None):
            law["errors"].append(f"보안 진단 실패 — 지난 진단 결과로 판정: {security.scan_error}")
    except SecurityError as e:
        sec, sec_err, sec_targets = None, str(e), set()
        law["errors"].append(sec_err)

    svcs = {}
    for s in services:
        prof, status, detail = loaded[s.id]
        entry = {"status": status, "detail": detail, "root": s.root, "findings": [], "summary": {},
                 "case_gaps": [], "benchmark_gaps": [], "custom_texts": bool(prof and prof.texts_dir)}
        if prof:
            f = law["findings"].get(prof.service, {})
            entry.update(findings=f.get("items", []), summary=f.get("summary", {}),
                         case_gaps=law["case_gaps"].get(prof.service, []),
                         benchmark_gaps=law["benchmark_gaps"].get(prof.service, []))
        if sec is None:
            entry["security"] = {"available": False, "detail": sec_err}
        elif s.id not in sec_targets:
            entry["security"] = {"available": False, "untracked": True,
                                 "detail": "ops/security targets.json 에 없음 — 코드 보안 진단을 안 함"}
        else:
            from .clauses import laws_for
            features = scope.get(s.id, {})
            opted = laws_for(features)  # 특징 → 적용 법령 리스트
            entry["security"] = {"available": True, **evaluate(sec.get(s.id, []), opted)}
        svcs[s.id] = entry

    report = {"checked_at": datetime.now().isoformat(timespec="seconds"), "services": svcs,
              "law": {k: v for k, v in law.items() if k not in ("findings", "case_gaps", "benchmark_gaps")},
              "warnings": warnings,
              "shared": {"findings": law["findings"].get("(공용 문구)", {}),
                         "case_gaps": law["case_gaps"].get("(공용 문구)", [])}}

    # 새 알림만
    prev_path = home / "reports" / "latest.json"
    prev = json.loads(prev_path.read_text(encoding="utf-8")) if prev_path.exists() else {}
    # alert_keys = 허브에 실제로 전달된 알림. 전달 못 한 것(--no-notify · 허브 실패)은 다음 바퀴에 다시 보낸다.
    # 사라진 알림은 빠지므로, 같은 문제가 다시 생기면 다시 알린다.
    # 일회성 이벤트(법령 개정 · 새 공지 · 처리방침 변경)는 감시가 '이번에 처음 본 것'만 돌려주므로,
    # 전달 못 한 것은 pending 에 두었다가 다음 바퀴에 다시 보낸다.
    seen = set(prev.get("alert_keys", []))
    alerts = _alerts(report)
    keys = {a["key"] for a in alerts}
    alerts += [a for a in prev.get("pending_alerts", []) if a["key"] not in keys]
    report["new_alerts"] = [a for a in alerts if a["key"] not in seen]
    delivered = set()
    delivery_errors = []
    if notify:
        for a in report["new_alerts"]:
            try:
                sent = hub.report(a["service"], a["event_type"], a["severity"], a["message"])
            except Exception as e:
                sent = False
                detail = f"허브 알림 전송 실패: {e}"
            else:
                detail = getattr(hub, "last_error", None) or "허브 알림 전송 실패"
            if sent:
                delivered.add(a["key"])
            else:
                delivery_errors.append(detail)
    if delivery_errors:
        warnings.append(f"허브 알림 {len(delivery_errors)}건 전송 실패: {delivery_errors[0]}")
    report["sent"] = len(delivered)
    report["alert_keys"] = sorted({a["key"] for a in alerts} & (seen | delivered))
    report["pending_alerts"] = [a for a in alerts if a["key"].startswith(ONE_SHOT)
                                and a["key"] not in seen and a["key"] not in delivered]

    prev_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = prev_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(prev_path)
    return report


def _sec_summary(sec: dict):
    if sec.get("untracked"):
        return "보안 미점검 (security 대상 아님)"
    if not sec.get("available"):
        return "결과 없음"
    return {"미흡": [f"{c['law']} {c['article']}: {c['count']}" for c in sec["clauses"] if c["count"]],
            "적용 제외": list(sec.get("skipped", {})),
            "조항 없는 규칙": sorted({f["rule"] for f in sec.get("unmapped", [])})}


def summary(report: dict) -> dict:
    """사람이 볼 한눈 요약."""
    law = report["law"]
    return {
        "checked_at": report["checked_at"],
        "laws": [f"{c['law']} (MST {c['mst']}, 시행 {c['effective']})" for c in law["checked"]],
        "law_changes": len(law["changed"]), "mapping_issues": len(law["mapping_issues"]),
        "stale_rules": len(law["stale_rules"]), "new_notices": len(law["notices"]),
        "violations": law.get("violations", {}), "manual_review": len(law["manual_review"]),
        "services": {sid: {"status": s["status"], **({"error": s["summary"].get("error", 0),
                                                        "warn": s["summary"].get("warn", 0),
                                                        "case_gaps": len(s["case_gaps"])} if s["status"] == "연결" else {}),
                              "security": _sec_summary(s.get("security") or {})}
                     for sid, s in report["services"].items()},
        "shared_text": report["shared"]["findings"].get("summary", {}),
        "errors": law["errors"], "warnings": report.get("warnings", []),
        "new_alerts": len(report["new_alerts"]), "sent": report["sent"],
    }
