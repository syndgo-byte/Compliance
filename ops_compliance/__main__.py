"""개인정보 · 컴플라이언스 명령줄.

  python -m ops_compliance run [--hub URL] [--no-notify]     한 바퀴 (요약 출력, 전체는 reports/latest.json)
  python -m ops_compliance serve [--every-hours 12]         주기 실행(이 창을 열어 두는 동안)
  python -m ops_compliance schedule install|remove|status   Windows 작업 스케줄러에 12시간마다 등록
  python -m ops_compliance report                           마지막 보고서 요약
  python -m ops_compliance rollout [--hub URL]              승인된 문구 개정의 서비스별 반영 상태
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from .checker import HOME, load_profile, run_cycle, summary
from .hub import HubClient

TASK = "MCPHub_ops_compliance"
EVERY_HOURS = 12


def _print(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=1))


def _schedule(action: str, every: int) -> int:
    if sys.platform != "win32":
        print("Windows 작업 스케줄러 전용입니다. 다른 OS 는 cron 에: "
              f"0 */{every} * * * {sys.executable} -m ops_compliance run")
        return 2
    if action == "install":
        cmd = f'cmd /c cd /d "{HOME}" && "{sys.executable}" -m ops_compliance run >> "{HOME / "reports" / "run.log"}" 2>&1'
        (HOME / "reports").mkdir(exist_ok=True)
        args = ["schtasks", "/Create", "/F", "/TN", TASK, "/SC", "HOURLY", "/MO", str(every), "/TR", cmd]
    elif action == "remove":
        args = ["schtasks", "/Delete", "/F", "/TN", TASK]
    else:
        args = ["schtasks", "/Query", "/TN", TASK, "/V", "/FO", "LIST"]
    r = subprocess.run(args, capture_output=True)
    out = (r.stdout or r.stderr).decode("cp949", "replace")
    print(out.strip())
    return r.returncode


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ops_compliance")
    ap.add_argument("--hub", default="http://127.0.0.1:8000")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("run")
    s.add_argument("--no-notify", action="store_true", help="허브 알림을 보내지 않음")
    s = sub.add_parser("serve")
    s.add_argument("--every-hours", type=float, default=EVERY_HOURS)
    s = sub.add_parser("schedule")
    s.add_argument("action", choices=["install", "remove", "status"])
    s.add_argument("--every-hours", type=int, default=EVERY_HOURS)
    sub.add_parser("report")
    sub.add_parser("rollout")
    a = ap.parse_args(argv)
    hub = HubClient(a.hub)

    if a.cmd == "run":
        _print(summary(run_cycle(hub=hub, notify=not a.no_notify)))
        return 0
    if a.cmd == "serve":
        while True:
            _print(summary(run_cycle(hub=hub)))
            time.sleep(a.every_hours * 3600)
    if a.cmd == "schedule":
        return _schedule(a.action, a.every_hours)
    if a.cmd == "report":
        p = HOME / "reports" / "latest.json"
        if not p.exists():
            print("보고서 없음 — python -m ops_compliance run")
            return 1
        _print(summary(json.loads(p.read_text(encoding="utf-8"))))
        return 0
    # rollout
    from privacy_law import DEFAULT_DIR, HOME as PL_HOME
    from privacy_law.suggestion_engine import ProposalStore
    from .rollout import rollout_status
    profiles = [p for p, _, _ in (load_profile(s) for s in hub.services()) if p]
    _print(rollout_status(profiles, Path(DEFAULT_DIR), ProposalStore(Path(PL_HOME) / "proposals")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
