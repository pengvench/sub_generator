"""Результаты: выбор узла, снимок состояния, персистентность (из runtime/core.py).

Модульные функции:
  _normalize_selection_strategy — round_robin/consistent_hash/sticky_session;
  _result_from_row              — XrayProbeResult из строки xray_working.json.

ResultsMixin входит в XrayCoreRuntime:
  snapshot            — снимок состояния для GUI;
  update_selection    — смена стратегии выбора узла (+рестарт);
  _select_active_result — стратегии (round-robin курсор, blake2b-хеш, sticky);
  _export_results     — xray_working.json / xray_rejected.json / pinged_subs.txt;
  _load_cached_results/_load_result_file — восстановление из кеша.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .parse import parse_node_link
from .procs import _resolve_binary
from .sorting import _reason_counts, _xray_result_sort_key
from .types import TELEGRAM_XRAY_PROBE_TOTAL, XrayNode, XrayProbeResult

__all__ = [
    "ResultsMixin",
    "_normalize_selection_strategy",
    "_result_from_row",
]


def _normalize_selection_strategy(strategy: str) -> str:
    normalized = str(strategy or "").strip()
    if normalized not in {"round_robin", "consistent_hash", "sticky_session"}:
        return "sticky_session"
    return normalized


def _result_from_row(row: dict[str, Any], *, accepted: bool) -> XrayProbeResult | None:
    node = parse_node_link(str(row.get("url") or ""), source_url=str(row.get("source") or "cache"))
    if node is None:
        return None
    try:
        latency = row.get("latency_ms")
        api_latency = row.get("api_latency_ms")
        dc_latency = row.get("dc_latency_ms")
        download = row.get("download_kbps")
        upload = row.get("upload_kbps")
        tg_media = row.get("tg_media_kbps")
        ai_country = str(row.get("ai_geo_country") or "").strip().upper()
        # Обратная совместимость: старые xray_working.json (созданные до введения
        # двухфазной проверки) не содержали поля fully_checked. Считать их
        # полностью проверенными НЕЛЬЗЯ — они прошли только быструю проверку,
        # а не полный стресс-тест. Поэтому без явного ключа fully_checked=True
        # запись считается лишь «пропингованной» (accepted, not fully_checked).
        fully_checked = bool(row.get("fully_checked", False))
        return XrayProbeResult(
            node=node,
            accepted=bool(row.get("accepted", accepted)),
            reason=str(row.get("reason") or ("ready" if accepted else "cached")),
            latency_ms=float(latency) if latency is not None else None,
            successes=int(row.get("successes") or (TELEGRAM_XRAY_PROBE_TOTAL if accepted else 0)),
            attempts=int(row.get("attempts") or TELEGRAM_XRAY_PROBE_TOTAL),
            runtime=str(row.get("runtime") or node.runtime),
            api_latency_ms=float(api_latency) if api_latency is not None else None,
            dc_latency_ms=float(dc_latency) if dc_latency is not None else None,
            download_kbps=float(download) if download is not None else None,
            upload_kbps=float(upload) if upload is not None else None,
            tg_media_kbps=float(tg_media) if tg_media is not None else None,
            ai_geo_country=ai_country if len(ai_country) == 2 else "",
            fully_checked=fully_checked,
        )
    except (TypeError, ValueError):
        return None


class ResultsMixin:
    """Выбор активного узла и персистентность результатов проверки."""

    # Атрибуты экземпляра (config/_lock/_process/...) создаются в
    # XrayCoreRuntime.__init__ (runtime/core.py) — примесь не имеет __init__.

    def snapshot(self) -> dict[str, Any]:
        rows = [item.row() for item in self.last_working]
        rejected_rows = [item.row() for item in self.last_rejected]
        pool_rows = rows + rejected_rows
        active = self.active_result.row() if self.active_result else None
        running = self.is_running()
        if active:
            latency_value = active.get("latency_ms")
            latency = ""
            if latency_value is not None:
                latency_number = float(latency_value)
                latency = f" · {'<1' if latency_number < 1 else str(int(round(latency_number)))} ms"
            active_text = (
                f"{active.get('protocol')} via {active.get('runtime')} · "
                f"{active.get('host')}:{active.get('port')} · {active.get('name')}{latency}"
            )
        else:
            active_text = ""
        return {
            "mode": "xray_core",
            "running": running,
            "local_running": running,
            "local_tg_url": self.local_tg_url,
            "local_url": self.local_proxy_url,
            "endpoint": self.config.endpoint,
            "status_text": "sing-box активен" if running else (self.last_error or ("sing-box ожидает перезапуск" if self.active_result else "sing-box остановлен")),
            "best_proxy": active_text,

            "active_node": active,
            "pool_rows": pool_rows,
            "xray_rejected_rows": rejected_rows,
            "ping_candidate_rows": [item.row() for item in self.ping_candidates],
            "working_count": len(rows),
            "ping_candidate_count": len(self.ping_candidates),
            "discovered_count": len(self.discovered_nodes),
            "rejected_count": len(rejected_rows),
            "unique_count": len(pool_rows),
            "balancer_strategy": _normalize_selection_strategy(self.config.selection_strategy),
            "manual_upstream_url": self.config.manual_upstream_url,
            "last_refresh_finished_at": self.last_refresh_finished_at,
            "active_download_kbps": self.active_download_kbps,
            "active_download_measured_at": self.active_download_measured_at,
            "reason_counts": _reason_counts(self.last_rejected),
            "xray_binary_found": bool(_resolve_binary(self.config.xray_binary_path, self.root_dir, "xray")),
            "sing_box_binary_found": bool(_resolve_binary(self.config.sing_box_binary_path, self.root_dir, "sing-box")),
        }

    def update_selection(self, selection_strategy: str, manual_upstream_url: str = "", *, restart: bool = True) -> None:
        with self._lock:
            self.config.selection_strategy = _normalize_selection_strategy(selection_strategy)
            self.config.manual_upstream_url = str(manual_upstream_url or "").strip()
            if self.config.manual_upstream_url and self.last_working and self._find_working_by_url(self.config.manual_upstream_url) is None:
                raise ValueError("xray node not found in accepted list")
            previous = self.active_result.node.key if self.active_result else None
            self._select_active_result(advance_round_robin=True)
            current = self.active_result.node.key if self.active_result else None
            if restart and previous != current and self.is_running():
                self.stop()
                if self.active_result is not None:
                    self._start_node(self.active_result.node, int(self.config.socks_port))
                    self._emit("xray_state", running=True, endpoint=self.config.endpoint)

    def _find_working_by_url(self, raw_url: str) -> XrayProbeResult | None:
        raw_url = str(raw_url or "").strip()
        return next((item for item in self.last_working if item.node.raw_url == raw_url), None)

    def _best_working_result(self) -> XrayProbeResult | None:
        return min(self.last_working, key=_xray_result_sort_key) if self.last_working else None

    def _select_active_result(self, *, advance_round_robin: bool) -> XrayProbeResult | None:
        ordered = sorted(self.last_working, key=_xray_result_sort_key)
        if not ordered:
            self.active_result = None
            return None

        manual = self._find_working_by_url(self.config.manual_upstream_url)
        if manual is not None:
            self.active_result = manual
            return manual

        strategy = _normalize_selection_strategy(self.config.selection_strategy)
        if strategy == "round_robin":
            index = self._round_robin_cursor % len(ordered)
            chosen = ordered[index]
            if advance_round_robin:
                self._round_robin_cursor = (self._round_robin_cursor + 1) % max(1, len(ordered))
        elif strategy == "consistent_hash":
            session_key = f"{self.config.socks_host}:{int(self.config.socks_port)}"
            digest = hashlib.blake2b(session_key.encode("utf-8", errors="ignore"), digest_size=8).digest()
            chosen = ordered[int.from_bytes(digest, "big") % len(ordered)]
        else:
            chosen = next((item for item in ordered if item.node.key == self._sticky_key), None)
            if chosen is None:
                chosen = ordered[0]
                self._sticky_key = chosen.node.key
        self.active_result = chosen
        return chosen

    def _export_results(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "xray_working.json").write_text(
            json.dumps([item.row() for item in self.last_working], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (self.out_dir / "xray_rejected.json").write_text(
            json.dumps([item.row() for item in self.last_rejected], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        # Кеш пропингованных подписок в txt (для тестов на заблокированной сети,
        # где подписки не импортируются). Содержит raw_url всех узлов, прошедших
        # быстрый пинг (ping_candidates) и полностью проверенных (last_working),
        # отсортированных по пингу.
        pinged = list(self.ping_candidates)
        for item in self.last_working:
            if not any(p.node.raw_url == item.node.raw_url for p in pinged):
                pinged.append(item)
        pinged_sorted = sorted(
            pinged,
            key=lambda r: (float("inf") if r.latency_ms is None else float(r.latency_ms)),
        )
        (self.out_dir / "pinged_subs.txt").write_text(
            "\n".join(item.node.raw_url for item in pinged_sorted) + ("\n" if pinged_sorted else ""),
            encoding="utf-8",
        )

    def load_pinged_subs(self) -> list[XrayNode]:
        """Загрузить пропингованные узлы из txt-кеша (pinged_subs.txt).

        Используется на заблокированной сети, где подписки не импортируются:
        берём сохранённые ранее пропингованные узлы и прогоняем по ним проверки.
        """
        path = self.out_dir / "pinged_subs.txt"
        if not path.exists():
            return []
        nodes: list[XrayNode] = []
        seen: set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = str(line).strip()
            if not raw or raw in seen:
                continue
            seen.add(raw)
            node = parse_node_link(raw, source_url="pinged_cache")
            if node is not None:
                nodes.append(node)
        return nodes


    def _load_cached_results(self) -> None:
        working_path = self.out_dir / "xray_working.json"
        rejected_path = self.out_dir / "xray_rejected.json"
        # Старые кеши (созданные до введения двухфазной проверки) в
        # xray_working.json содержат все принятые записи без поля fully_checked.
        # Такие записи — только «пропингованные» кандидаты, а не полностью
        # проверенные рабочие. Раскладываем их по соответствующим спискам, иначе
        # GUI после обновления поверх покажет всех старых «рабочих».
        loaded = self._load_result_file(working_path, accepted=True)
        self.last_working = [item for item in loaded if item.fully_checked]
        self.ping_candidates = [item for item in loaded if not item.fully_checked]
        self.last_rejected = self._load_result_file(rejected_path, accepted=False)
        if self.last_working:
            self.last_refresh_finished_at = working_path.stat().st_mtime
            self._select_active_result(advance_round_robin=False)
            self._log(
                f"[xray] loaded {len(self.last_working)} cached fully-checked nodes, "
                f"{len(self.ping_candidates)} ping candidates"
            )

    def _load_result_file(self, path: Path, *, accepted: bool) -> list[XrayProbeResult]:
        if not path.exists():
            return []
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        results: list[XrayProbeResult] = []
        if not isinstance(rows, list):
            return results
        for row in rows:
            if not isinstance(row, dict):
                continue
            # Пропускаем заведомо мусорные записи: падение NDT7 (UnboundLocalError
            # в _mlab_fetch_target, исправлено) ловилось except и писало reason с
            # текстом исключения, а не причину отклонения узла.
            reason = str(row.get("reason") or "")
            if reason.startswith("cannot access local variable") or "is not associated with a value" in reason:
                continue
            result = _result_from_row(row, accepted=accepted)
            if result is not None:
                results.append(result)
        return sorted(results, key=_xray_result_sort_key)
