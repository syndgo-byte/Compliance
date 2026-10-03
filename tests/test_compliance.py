import json
import os
from pathlib import Path

import pytest

from ops_compliance.checker import load_profile, run_cycle, summary
from ops_compliance.hub import DEFAULT_HUB_URL, HubClient, HubError, ServiceInfo
from ops_compliance.clauses import CLAUSES, ECOMMERCE, EFIN, evaluate, laws_for
from ops_compliance.rollout import rollout_status
from ops_compliance.security import SecurityClient, SecurityError
from privacy_law import DEFAULT_DIR
from privacy_law.profile import ServiceProfile
from privacy_law.suggestion_engine import ProposalStore


class FakeHub:
    """허브 HTTP 흉내: /hub/graph, /hub/manifest/{id}, /monitor/events."""

    def __init__(self, manifests):
        self.manifests = manifests
        self.posted = []

    def get(self, url):
        path = url.split("8000", 1)[1]
        if path == "/hub/graph":
            nodes = [{"id": i, "kind": m.get("kind", "service")} for i, m in self.manifests.items()]
            return json.dumps({"nodes": nodes}).encode()
        sid = path.rsplit("/", 1)[1]
        return json.dumps(self.manifests[sid]).encode()

    def post(self, url):
        self.posted.append(url)
        return b"{}"

    def client(self):
        return HubClient("http://127.0.0.1:8000", get=self.get, post=self.post)


class FakeSec:
    def __init__(self, rows=None, down=False, targets=None):
        self.rows, self.down, self.targets = rows or {}, down, targets

    def active_findings(self):
        if self.down:
            raise SecurityError("security 꺼짐")
        return self.rows

    def code_targets(self):
        class _All:                      # targets 미지정 = 모든 서비스가 진단 대상
            def __contains__(self, _):
                return True
        return _All() if self.targets is None else set(self.targets)


NOSEC = FakeSec()


def _profile(root: Path, service: str, **extra):
    d = {"service": service, "values": {"service_name": service}, **extra}
    (root / "privacy_profile.json").write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")


def _watch(result):
    calls = []

    def run(*, profiles):
        calls.append([p.service for p in profiles])
        return json.loads(json.dumps(result))
    run.calls = calls
    return run


LAW = {"checked": [{"law": "개인정보 보호법", "mst": "283839", "effective": "20260911"}],
       "changed": [], "errors": [], "mapping_issues": [], "stale_rules": [], "notices": [],
       "manual_review": [], "policy_changes": [], "violations": {"29": 4},
       "findings": {"shop": {"items": [{"rule": "P30-6", "doc": "privacy", "severity": "error",
                                        "message": "보호책임자 없음"}],
                             "summary": {"error": 1, "warn": 0}},
                    "(공용 문구)": {"items": [], "summary": {"error": 4, "warn": 1}}},
       "case_gaps": {"shop": [{"article": "29", "message": "안전조치 처분 4건 — 문구 확인"}]},
       "benchmark_gaps": {"shop": [{"topic": "가명정보", "action": "기재 필요", "sites": 2},
                                   {"topic": "위치정보", "action": "해당 시에만", "sites": 2}]}}


def test_hub_services_only_web_services(tmp_path):
    hub = FakeHub({"shop": {"provides": ["privacy.values"], "source": {"root": str(tmp_path)}},
                   "auth_core": {"kind": "module", "provides": ["auth"]}})
    svcs = hub.client().services()
    assert [s.id for s in svcs] == ["shop"] and svcs[0].connected and svcs[0].root == str(tmp_path)


def test_hub_down_is_hub_error():
    def boom(url):
        raise OSError("refused")
    with pytest.raises(HubError, match="GET .*/hub/graph"):
        HubClient(get=boom).services()


def test_hub_default_and_post_failure_detail():
    assert DEFAULT_HUB_URL == os.getenv("MCP_HUB_URL", "http://127.0.0.1:9890")

    def down(url):
        raise OSError("refused")

    hub = HubClient(post=down)
    assert hub.report("shop", "change", "high", "test") is False
    assert f"POST {DEFAULT_HUB_URL}/monitor/events/shop" in hub.last_error
    assert "refused" in hub.last_error


def test_profile_statuses(tmp_path):
    assert load_profile(ServiceInfo("a", str(tmp_path), []))[1] == "미연결"
    assert load_profile(ServiceInfo("a", None, ["privacy.values"]))[1] == "프로필 오류"
    assert load_profile(ServiceInfo("a", str(tmp_path), ["privacy.values"]))[1] == "프로필 오류"   # 파일 없음
    _profile(tmp_path, "other")
    p, st, detail = load_profile(ServiceInfo("a", str(tmp_path), ["privacy.values"]))
    assert p is None and st == "프로필 오류" and "허브 id" in detail
    _profile(tmp_path, "a")
    p, st, _ = load_profile(ServiceInfo("a", str(tmp_path), ["privacy.values"]))
    assert st == "연결" and p.service == "a"


def test_cycle_reports_and_sends_only_new_alerts(tmp_path):
    shop = tmp_path / "shop"
    shop.mkdir()
    _profile(shop, "shop")
    hub = FakeHub({"shop": {"provides": ["privacy.values"], "source": {"root": str(shop)}},
                   "demo": {"provides": [], "source": {"root": str(tmp_path)}}})
    watch = _watch(LAW)
    home = tmp_path / "home"

    r = run_cycle(hub=hub.client(), watch=watch, home=home, security=NOSEC)
    assert watch.calls == [["shop"]]
    assert r["services"]["demo"]["status"] == "미연결"
    s = r["services"]["shop"]
    assert s["status"] == "연결" and s["summary"]["error"] == 1 and len(s["case_gaps"]) == 1
    assert r["shared"]["findings"]["summary"]["error"] == 4
    keys = {a["key"] for a in r["new_alerts"]}
    assert {"svc:demo:unlinked", "svc:shop:rule:P30-6:privacy", "svc:shop:case:29", "svc:shop:bench:가명정보"} == keys
    assert r["sent"] == 4 and len(hub.posted) == 4
    sev = {a["key"]: a["severity"] for a in r["new_alerts"]}
    assert sev["svc:shop:rule:P30-6:privacy"] == "high" and sev["svc:demo:unlinked"] == "low"
    assert sum("/monitor/events/shop?" in u and "severity=high" in u for u in hub.posted) == 1
    assert (home / "reports" / "latest.json").exists()
    sm = summary(r)
    assert sm["services"]["shop"] == {"status": "연결", "error": 1, "warn": 0, "case_gaps": 1, "security": {"미흡": [], "적용 제외": ["전자금융감독규정", "전자상거래 등에서의 소비자보호에 관한 법률"], "조항 없는 규칙": []}}

    # 두 번째 바퀴: 같은 결과면 알림 없음
    r2 = run_cycle(hub=hub.client(), watch=watch, home=home, security=NOSEC)
    assert r2["new_alerts"] == [] and len(hub.posted) == 4

    # 법령 개정이 생기면 그것만 새로
    law = json.loads(json.dumps(LAW))
    law["changed"] = [{"law": "개인정보 보호법", "mst": "300000", "effective": "20270101",
                       "articles": ["22"], "proposals": ["p1"]}]
    r3 = run_cycle(hub=hub.client(), watch=_watch(law), home=home, security=NOSEC)
    assert [a["key"] for a in r3["new_alerts"]] == ["law:개인정보 보호법:300000"]
    assert r3["new_alerts"][0]["severity"] == "high" and r3["new_alerts"][0]["service"] == "compliance"


def test_cycle_survives_hub_down_and_watch_crash(tmp_path):
    def boom(url):
        raise OSError("refused")

    def crash(*, profiles):
        raise RuntimeError("법제처 응답 없음")
    r = run_cycle(hub=HubClient(get=boom, post=boom), watch=crash, home=tmp_path, security=FakeSec(down=True))
    errs = r["law"]["errors"]
    assert any("허브" in e for e in r["warnings"]) and any("법제처 응답 없음" in e for e in errs)
    assert any("security 꺼짐" in e for e in errs)
    assert r["services"] == {} and r["sent"] == 0      # 보낼 곳도 죽어 있으면 0
    assert (tmp_path / "reports" / "latest.json").exists()
    assert summary(r)["warnings"] == r["warnings"]


def test_no_notify(tmp_path):
    hub = FakeHub({"demo": {"provides": []}})
    r = run_cycle(hub=hub.client(), watch=_watch(LAW), home=tmp_path, notify=False, security=NOSEC)
    assert r["new_alerts"] and hub.posted == [] and r["sent"] == 0
    # 미리보기(--no-notify) 뒤 실제 실행에서는 보내야 한다
    r = run_cycle(hub=hub.client(), watch=_watch(LAW), home=tmp_path, security=NOSEC)
    assert r["sent"] == len(r["new_alerts"]) > 0 and len(hub.posted) == r["sent"]


def test_failed_delivery_retried(tmp_path):
    hub = FakeHub({"demo": {"provides": []}})

    def down(url):
        raise OSError("hub down")
    flaky = HubClient("http://127.0.0.1:8000", get=hub.get, post=down)
    r = run_cycle(hub=flaky, watch=_watch(LAW), home=tmp_path, security=NOSEC)
    assert r["new_alerts"] and r["sent"] == 0 and r["alert_keys"] == []
    assert any("POST http://127.0.0.1:8000/monitor/events/demo" in w for w in r["warnings"])
    assert json.loads((tmp_path / "reports" / "latest.json").read_text(encoding="utf-8"))["warnings"] == r["warnings"]
    r = run_cycle(hub=hub.client(), watch=_watch(LAW), home=tmp_path, security=NOSEC)
    assert r["sent"] == 1 and "svc:demo:unlinked" in r["alert_keys"]


SEC_SRC = Path("D:/Vibe_coding/ops/security/security/scanners")


@pytest.mark.skipif(not SEC_SRC.exists(), reason="ops/security 소스 없음")
def test_clause_rules_exist_in_security_scanners():
    """매핑표의 규칙 ID 는 security 진단기가 실제로 내는 것이어야 한다(오타 · 이름 변경 감지)."""
    src = "\n".join(p.read_text(encoding="utf-8") for p in SEC_SRC.glob("*.py"))
    missing = [r for c in CLAUSES for r in c["rules"] if f'"{r}"' not in src]
    assert missing == []


def test_evaluate_groups_by_clause():
    rows = [{"id": "1", "rule": "LEGAL-NO-MFA", "severity": "medium", "title": "t", "file": "a.py", "line": 1},
            {"id": "2", "rule": "PIPA-UNIQUE-ID-PLAINTEXT", "severity": "high", "title": "t", "file": "m.py", "line": 3},
            {"id": "3", "rule": "SAST-PY-SQLI", "severity": "high", "title": "t", "file": "b.py", "line": 9}]
    r = evaluate(rows)
    by = {c["article"]: c for c in r["clauses"]}
    assert by["제6조②"]["status"] == "미흡" and by["제7조②"]["worst"] == "high"
    assert by["제8조①"]["status"] == "신호 없음" and by["제8조①"]["count"] == 0
    assert r["unmapped"] == []                       # SAST-PY-SQLI 는 지침 별표1 2.2.7 에 붙음
    assert by["별표1 2.2.7"]["status"] == "미흡"
    assert all(c["law"] != "전자금융감독규정" for c in r["clauses"]) and "전자금융감독규정" in r["skipped"]
    assert [u["rule"] for u in evaluate([dict(rows[0], rule="DEPS-OSV-UNREACHABLE")])["unmapped"]] == ["DEPS-OSV-UNREACHABLE"]
    # 같은 규칙이 여러 법령 조항에 걸린다
    hits = [(c["law"], c["article"]) for c in evaluate(rows[1:2])["clauses"] if c["count"]]
    assert ("개인정보의 안전성 확보조치 기준", "제7조②") in hits and ("정보보호조치에 관한 지침", "별표1 2.2.13") in hits


def test_efin_opt_in_via_scope(tmp_path):
    rows = [{"id": "1", "rule": "LEGAL-NO-LOGIN-LOCKOUT", "severity": "medium", "title": "t", "file": "a.py", "line": 1}]
    assert not any(c["count"] for c in evaluate(rows)["clauses"])        # 전자금융 미적용이면 이 규칙은 걸릴 조항 없음
    by = {c["article"]: c for c in evaluate(rows, ["전자금융감독규정"])["clauses"]}
    assert by["제34조의3②1·2호"]["status"] == "미흡"
    hub = FakeHub({"pay": {"provides": []}})
    sec = FakeSec({"pay": [dict(rows[0], status="open")]})
    # 특징 기반 scope: direct_payment=true면 전자금융감독규정 적용
    (tmp_path / "scope.json").write_text(json.dumps({"pay": {"direct_payment": True}}, ensure_ascii=False), encoding="utf-8")
    r = run_cycle(hub=hub.client(), watch=_watch(LAW), home=tmp_path, security=sec, notify=False)
    assert any("제34조의3" in a["message"] for a in r["new_alerts"])
    # 옛 형식(list)은 오류 발생
    (tmp_path / "scope.json").write_text(json.dumps({"pay": ["전자금융감독규정"]}), encoding="utf-8")
    r = run_cycle(hub=hub.client(), watch=_watch(LAW), home=tmp_path, security=sec, notify=False)
    assert any("scope.json" in e for e in r["law"]["errors"])


@pytest.mark.parametrize(
    ("features", "expected"),
    [({}, set()),
     ({"sales": True, "direct_payment": False}, {ECOMMERCE}),
     ({"sales": False, "direct_payment": True}, {EFIN}),
     ({"sales": True, "direct_payment": True}, {ECOMMERCE, EFIN}),
     ({"sales": False, "direct_payment": False, "location": True, "public": True}, set())],
)
def test_laws_for_features(features, expected):
    selected = set(laws_for(features))
    assert selected & {ECOMMERCE, EFIN} == expected


def test_sales_scope_applies_only_to_selected_service(tmp_path):
    finding = {"id": "1", "rule": "WEB-NO-HTTPS", "severity": "high", "title": "t",
               "file": "a.py", "line": 1, "status": "open"}
    hub = FakeHub({"shop": {"provides": []}, "info": {"provides": []}})
    sec = FakeSec({"shop": [finding], "info": [finding]})
    (tmp_path / "scope.json").write_text(
        json.dumps({"shop": {"sales": True}, "info": {"sales": False}}), encoding="utf-8")

    report = run_cycle(hub=hub.client(), watch=_watch(LAW), home=tmp_path,
                       security=sec, notify=False)
    shop = report["services"]["shop"]["security"]
    info = report["services"]["info"]["security"]
    assert ECOMMERCE in shop["laws"] and ECOMMERCE not in shop["skipped"]
    assert ECOMMERCE not in info["laws"] and ECOMMERCE in info["skipped"]
    assert EFIN in shop["skipped"] and EFIN in info["skipped"]
    assert [(c["article"], c["count"]) for c in shop["clauses"]
            if c["law"] == ECOMMERCE] == [("제13조", 1), ("제21조의2", 0)]
    assert any(a["key"] == f"svc:shop:sec:{ECOMMERCE}:제13조" for a in report["new_alerts"])
    assert not any(a["key"].startswith(f"svc:info:sec:{ECOMMERCE}:") for a in report["new_alerts"])


def test_security_client_filters_active():
    rows = [{"service": "a", "status": "open", "rule": "X"}, {"service": "a", "status": "applied", "rule": "Y"},
            {"service": "b", "status": "delivered", "rule": "Z"}]
    c = SecurityClient(get=lambda url: json.dumps(rows).encode())
    assert {k: [r["rule"] for r in v] for k, v in c.active_findings().items()} == {"a": ["X"], "b": ["Z"]}

    def boom(url):
        raise OSError("x")
    with pytest.raises(SecurityError):
        SecurityClient(get=boom).active_findings()


def test_cycle_security_alerts(tmp_path):
    hub = FakeHub({"shop": {"provides": []}})
    sec = FakeSec({"shop": [{"id": "1", "rule": "PIPA-UNIQUE-ID-PLAINTEXT", "severity": "high", "title": "t",
                             "file": "m.py", "line": 3, "status": "open"}]})
    r = run_cycle(hub=hub.client(), watch=_watch(LAW), home=tmp_path, security=sec)
    a = [x for x in r["new_alerts"] if ":sec:" in x["key"]]
    assert len(a) == 2 and all(x["severity"] == "high" for x in a) and any("제7조②" in x["message"] for x in a)
    assert summary(r)["services"]["shop"]["security"]["미흡"] == ["개인정보의 안전성 확보조치 기준 제7조②: 1",
                                                          "정보보호조치에 관한 지침 별표1 2.2.13: 1"]
    r2 = run_cycle(hub=hub.client(), watch=_watch(LAW), home=tmp_path, security=FakeSec(down=True))
    assert r2["services"]["shop"]["security"]["available"] is False
    assert summary(r2)["services"]["shop"]["security"] == "결과 없음"


def test_rollout(tmp_path):
    own = tmp_path / "own"
    own.mkdir()
    shared = json.loads((Path(DEFAULT_DIR) / "documents.json").read_text(encoding="utf-8"))
    old = [dict(d, version="2000-01-01") if d["key"] == "privacy" else d for d in shared]
    (own / "documents.json").write_text(json.dumps(old, ensure_ascii=False), encoding="utf-8")
    store = ProposalStore(tmp_path / "proposals")
    m = store.create(doc_key="privacy", doc_title="개인정보 처리방침", law="개인정보 보호법", mst="1",
                     effective="20260911", changes=[], current_html="<p>a</p>", prompt="")
    store.update(m["id"], status="approved", old_version="2000-01-01", new_version="2026-09-30")
    store.create(doc_key="terms", doc_title="약관", law="x", mst="1", effective="1", changes=[],
                 current_html="", prompt="")

    r = rollout_status([ServiceProfile(service="a"), ServiceProfile(service="b", texts_dir=str(own)),
                        ServiceProfile(service="c", texts_dir=str(tmp_path / "none"))], Path(DEFAULT_DIR), store)
    assert [c["doc_key"] for c in r["approved"]] == ["privacy"]
    assert r["services"]["a"]["mode"] == "공용 문구" and r["services"]["a"]["behind"] == []
    assert [b["doc"] for b in r["services"]["b"]["behind"]] == ["privacy"]
    assert "읽지 못함" in r["services"]["c"]["note"]


def test_service_not_in_security_targets(tmp_path):
    from ops_compliance.checker import run_cycle, summary
    svcs = [ServiceInfo("a", str(tmp_path)), ServiceInfo("b", str(tmp_path))]
    sec = FakeSec({"a": [{"rule": "HARD-BIND-ALL", "severity": "medium", "status": "open", "service": "a"}]},
                  targets=["a"])
    r = run_cycle(hub=FakeHub({}).client(), services=svcs, watch=lambda profiles: {}, security=sec, home=tmp_path, notify=False)
    assert r["services"]["a"]["security"]["available"]
    assert r["services"]["b"]["security"]["untracked"]
    s = summary(r)["services"]
    assert s["b"]["security"].startswith("보안 미점검")
    assert "개인정보의 안전성 확보조치 기준 제6조①1호: 1" in s["a"]["security"]["미흡"]
    assert "전자금융감독규정" in s["a"]["security"]["적용 제외"]
    assert any(a["key"] == "svc:b:sec:untracked" for a in r["new_alerts"])


def test_security_client_targets():
    from ops_compliance.security import SecurityClient
    c = SecurityClient(get=lambda url: json.dumps({"code": {"x": "D:/x"}, "web": {}}).encode())
    assert c.code_targets() == {"x"}


def test_one_shot_events_kept_until_delivered(tmp_path):
    """감시가 한 번만 주는 이벤트(새 공지)는 --no-notify · 허브 실패여도 다음 바퀴에 보낸다."""
    notice = {"board": "공지사항", "ntt_id": "1", "title": "고시 개정", "topics": ["안전조치"], "url": "u"}
    first = lambda profiles: {"notices": [notice]}
    later = lambda profiles: {}
    kw = dict(services=[], security=NOSEC, home=tmp_path)
    r1 = run_cycle(hub=FakeHub({}).client(), watch=first, notify=False, **kw)
    assert [a["key"] for a in r1["pending_alerts"]] == ["notice:공지사항:1"]
    hub = FakeHub({})
    r2 = run_cycle(hub=hub.client(), watch=later, notify=True, **kw)
    assert r2["sent"] == 1 and len(hub.posted) == 1 and r2["pending_alerts"] == []
    r3 = run_cycle(hub=hub.client(), watch=later, notify=True, **kw)
    assert r3["new_alerts"] == [] and len(hub.posted) == 1


def test_security_cli_scans_then_reads(tmp_path):
    """security 를 상주시키지 않고 한 바퀴마다 scan → list --json · targets 를 부른다."""
    from types import SimpleNamespace
    from ops_compliance.security import SecurityCLI
    calls = []
    rows = [{"service": "a", "rule": "HARD-BIND-ALL", "severity": "medium", "status": "open"},
            {"service": "a", "rule": "X", "severity": "low", "status": "dismissed"}]

    def run(cmd, **kw):
        calls.append(cmd[3:])
        out = {"scan": "", "list": json.dumps(rows), "targets": json.dumps({"code": {"a": "D:/a"}, "web": {}})}
        return SimpleNamespace(returncode=0, stdout=out[cmd[3]], stderr="")
    c = SecurityCLI(home=tmp_path, run=run)
    assert c.active_findings() == {"a": [rows[0]]} and c.code_targets() == {"a"}
    c.active_findings()
    assert calls == [["scan"], ["list", "--json"], ["targets"], ["list", "--json"]]     # scan 은 한 번만


def test_security_cli_scan_failure_still_judges(tmp_path):
    from types import SimpleNamespace
    from ops_compliance.security import SecurityCLI

    def run(cmd, **kw):
        if cmd[3] == "scan":
            return SimpleNamespace(returncode=1, stdout="", stderr="OSV 연결 실패")
        return SimpleNamespace(returncode=0, stdout=json.dumps([] if cmd[3] == "list" else {"code": {}}), stderr="")
    svcs = [ServiceInfo("a", str(tmp_path))]
    r = run_cycle(hub=FakeHub({}).client(), services=svcs, watch=lambda profiles: {},
                  security=SecurityCLI(home=tmp_path, run=run), home=tmp_path, notify=False)
    assert any("보안 진단 실패" in e and "OSV" in e for e in r["law"]["errors"])
