# 개인정보 · 컴플라이언스 (ops_compliance)

마지막 업데이트: 2026-10-05 22:40 (Asia/Seoul)

12시간마다 법령 · 개인정보위 · 외부 처리방침 감시(Privacy_Law)와 ops/security 진단 결과를 모아
**서비스별로 어느 법 조항이 미흡한지** 판정하고, 새로 생긴 것만 MCP Hub 관제판에 알린다.

## 역할 나눔

| 누가 | 하는 일 |
|---|---|
| ops/security | 코드 · 설정 · 웹 기술 진단 → findings. 평소엔 필요할 때 직접 실행. compliance 가 12시간마다 `python -m security scan` 을 한 번 돌려 결과를 읽는다(상주 서버 불필요) |
| modules/Privacy_Law | 법령 개정 감시, 개인정보위 공지 · 처분 공표, 처리방침 벤치마크, 동의 문구 점검 |
| **ops/compliance (여기)** | 위 둘을 **읽기만** 해서 법 조항별 준수 판정 → reports/latest.json · 허브 알림 |
| MCP Hub | 결과 표시 · 실행 버튼만. 점검 로직 없음 |

compliance 는 security 에 판정 결과를 보내지 않는다. 진단 실패 시 지난 진단 결과로 판정하고 오류에 남긴다.
`OPS_SECURITY_HOME`(기본 D:\Vibe_coding\ops\security)으로 위치를 바꿀 수 있다.

## 판정하는 법령 (clauses.py)

조항 본문은 법제처 행정규칙 API 현행본(2026-09-30 조회) 기준.

- 개인정보의 안전성 확보조치 기준 (개인정보위 고시) — 모든 서비스
- 정보보호조치에 관한 지침 [별표 1] (과기정통부 고시) — 모든 웹 서비스 (정보통신망법 제45조③)
- 전자금융감독규정 (금융위 고시) — **특징 기반**. 금융회사 · 전자금융업자 · 직접 결제 처리 시 `scope.json` 에서 켠다:
- 전자상거래 등에서의 소비자보호에 관한 법률 — **특징 기반**. 온라인 판매·구독 서비스 제공 시 켠다.

```json
{"<서비스ID>": {"sales": true/false, "location": true/false, "direct_payment": true/false, "public": true/false}}
```

EMSv3 는 전자상거래(판매)와 직접 결제를 하므로:
```json
{"EMSv3": {"sales": true, "direct_payment": true, "location": false, "public": false}}
```

조항마다 security 규칙 ID 를 연결했다. 결과는 `미흡`(규칙에 걸림) 또는 `신호 없음`.
**신호 없음은 충족 증명이 아니다.** 조직 · 절차 · 물리 조치(내부 관리계획, 교육, 출입통제)는 코드로 볼 수 없어 표에 없다.
국정원 국가 정보보안 기본지침은 법제처 API 에 없고 공공기관 대상이라 넣지 않았다.

## 서비스 상태

- 개인정보: `연결` / `미연결`(privacy.values 미제공) / `프로필 오류`
- 보안: 조항별 결과 / `보안 미점검`(security targets.json 에 없음) / `결과 없음`(security 진단 실패)

## 알림

- 같은 알림은 반복하지 않는다(`alert_keys`). 문제가 사라졌다가 다시 생기면 다시 알린다.
- `--no-notify` 이거나 허브가 실패해 전달 못 한 알림은 다음 바퀴에 다시 보낸다.
- 한 번만 오는 이벤트(법령 개정 · 새 공지 · 처리방침 변경)는 전달될 때까지 `pending_alerts` 에 보관.

## 실행

```
python -m ops_compliance run [--no-notify]      # 한 바퀴
python -m ops_compliance report                  # 최근 결과 요약
python -m ops_compliance rollout                 # 승인된 문구 개정의 서비스별 반영 상태
python -m ops_compliance schedule install|remove|status   # Windows 작업 스케줄러 12시간마다 (MCPHub_ops_compliance)
```

**운영은 작업 스케줄러로만 한다** — 12시간마다 한 바퀴 돌고 끝난다. 상주 프로세스 없음.

필요: Privacy_Law 가 import 가능해야 함, ops/security 폴더, 허브(기본 127.0.0.1:8100, 알림 전달용 — 꺼져 있으면 다음 바퀴에 다시 보냄). 허브 주소가 다르면 `MCP_HUB_URL` 환경 변수 또는 `--hub URL` 로 지정한다.
법령은 법제처 웹 화면(law.go.kr)에서 최신본을 읽는다 — 인증키(LAW_OC) 필요 없음. 저장돼 있으면 Open API 사용.

테스트: `PYTHONPATH=".;D:/Vibe_coding/modules/Privacy_Law" python -m pytest tests -q`
