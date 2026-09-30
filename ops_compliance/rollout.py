"""승인된 문구 개정이 서비스마다 반영됐는지.

공용 문구(Privacy_Law texts/)를 쓰는 서비스는 파일이 바뀌는 즉시 반영된다 — 남는 일은 재동의(outdated) 뿐.
전용 문서 폴더(profile.texts_dir)를 쓰는 서비스는 자동 반영되지 않으므로, 그 폴더의 documents.json 버전을
공용 버전과 비교해 뒤처진 문서를 알려 준다.
"""
from __future__ import annotations

import json
from pathlib import Path


def _versions(texts_dir: Path) -> dict[str, str]:
    return {d["key"]: str(d["version"]) for d in json.loads((Path(texts_dir) / "documents.json").read_text(encoding="utf-8"))}


def approved_changes(store) -> list[dict]:
    """privacy_law ProposalStore 에서 승인된 개정 (최신순)."""
    return [{k: p.get(k) for k in ("id", "doc_key", "doc_title", "law", "effective", "old_version", "new_version",
                                   "decided_at", "decided_by")} for p in store.all() if p["status"] == "approved"]


def rollout_status(profiles: list, shared_dir: Path, store=None) -> dict:
    shared = _versions(shared_dir)
    changes = approved_changes(store) if store is not None else []
    out = {"shared_versions": shared, "approved": changes, "services": {}}
    for prof in profiles:
        if not prof.texts_dir:
            out["services"][prof.service] = {
                "mode": "공용 문구", "behind": [],
                "note": "공용 문구를 그대로 씀 — 개정은 즉시 반영, 버전이 오른 필수 문서는 서비스 재로그인 때 재동의(outdated)"}
            continue
        try:
            own = _versions(Path(prof.texts_dir))
        except (OSError, ValueError, KeyError) as e:
            out["services"][prof.service] = {"mode": "전용 문서", "behind": [], "note": f"전용 문서 폴더를 읽지 못함: {e}"}
            continue
        behind = [{"doc": k, "service_version": own.get(k), "shared_version": v}
                  for k, v in shared.items() if own.get(k) != v and (own.get(k) or "") < v]
        out["services"][prof.service] = {
            "mode": "전용 문서", "behind": behind,
            "note": ("공용 개정이 전용 문서에 반영되지 않음 — 비교 후 직접 반영" if behind else "공용 버전과 같거나 더 최신")}
    return out
