"""Сквозная трассировка узлов по подпискам: воронка потерь от discovery до экспорта.

Запрос пользователя (2026-09-19, лог.zip): «половина подписок — хороших
подписок — тупо теряются хрен пойми где. Давай вести лог от самого начала,
какие конфиги закреплены за какими подписками — чтобы точно понимать где
отвалились».

Модуль держит реестр «ключ узла → источник (подписка)» и серию чекпойнтов
по стадиям конвейера. На каждом чекпойнте фиксируется, кто ещё жив; узлы,
не дожившие до чекпойнта, получают стадию и причину отвала.

Артефакты:
  * data/trace.log — человекочитаемая воронка по каждому источнику,
    переписывается после каждой стадии (краш на середине оставляет
    частичную трассировку — как pending-отчёт в report.json);
  * report.json → секция "trace": воронка по источникам + судьба каждого
    узла, дожившего до quick-пинга (дальше — агрегаты по причинам).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Iterable

# Стадии в порядке конвейера. «discovered» — точка регистрации (после дедупа).
# v16: добавлена стадия «dpi_active» (инцидент лог2: 35 узлов, убитых
# dpi-активом с reason=control_failed/dpi_signature_unstable, приписывались
# ai_geo с безликим «—» — юзер не видел, ГДЕ именно они отвалились).
STAGES: list[str] = [
    "discovered",
    "quick",
    "max_ping",
    "initial",
    "telegram",
    "services",
    "resilience",
    "dpi_active",
    "ai_geo",
    "recheck",
    "exported",
]
_STAGE_IDX = {name: i for i, name in enumerate(STAGES)}

_UNKNOWN = "(источник неизвестен)"


def trace_key(obj: Any) -> str:
    """Ключ узла в формате host:port/digest8 — совместим с _detail_key."""
    node = getattr(obj, "node", None)
    if node is None and hasattr(obj, "key"):
        node = obj
    if node is None:
        return str(id(obj))
    try:
        proto, host, port, digest = node.key
        return f"{host}:{port}/{digest[:8]}"
    except Exception:
        return f"{getattr(node, 'host', '?')}:{getattr(node, 'port', '?')}"


def node_source(obj: Any) -> str:
    """Источник узла: работает и с голым XrayNode, и с обёрткой-результатом."""
    node = getattr(obj, "node", None)
    if node is None and hasattr(obj, "source_url"):
        node = obj
    src = str(getattr(node, "source_url", "") or "").strip() if node is not None else ""
    return src or _UNKNOWN


class FunnelTracker:
    """Реестр узлов по источникам + чекпойнты стадий.

    Потокобезопасность: все вызовы делаются из главного потока конвейера
    (между стадиями), параллельные воркеры трекер не трогают.
    """

    def __init__(self) -> None:
        # key → {"source", "stage" (последний пройденный чекпойнт),
        #         "drop_stage", "drop_reason"}
        self._nodes: dict[str, dict[str, Any]] = {}
        self._sources: dict[str, int] = {}  # источник → сколько узлов зарегистрировано
        self._checkpoints: list[str] = []   # какие чекпойнты уже прошли

    # ------------------------------------------------------------------
    # Регистрация и чекпойнты
    # ------------------------------------------------------------------
    def register(self, nodes: Iterable[Any]) -> int:
        """Зарегистрировать найденные узлы (стадия discovered).

        Вызывается один раз после дедупа; повторная регистрация тех же
        ключей идемпотентна (данные не перезаписываются).
        """
        added = 0
        for obj in nodes:
            key = trace_key(obj)
            if key in self._nodes:
                continue
            src = node_source(obj)
            self._nodes[key] = {
                "source": src,
                "stage": 0,
                "drop_stage": None,
                "drop_reason": None,
            }
            self._sources[src] = self._sources.get(src, 0) + 1
            added += 1
        return added

    def checkpoint(
        self,
        stage: str,
        alive: Iterable[Any],
        drop_reasons: dict[str, str] | None = None,
    ) -> None:
        """Зафиксировать выживших на стадии ``stage``.

        ``alive`` — объекты узлов (XrayNode или обёртки), дожившие до
        следующей стадии. Узлы, зарегистрированные ранее и НЕ пришедшие
        сюда, считаются отвалившимися на этой стадии (если они ещё не были
        помечены отвалившимися раньше). ``drop_reasons`` — причина отвала
        по ключу узла (из деталей стадии), для отсутствующих — «—».
        """
        idx = _STAGE_IDX.get(stage)
        if idx is None:
            return
        self._checkpoints.append(stage)
        alive_keys = {trace_key(obj) for obj in alive}
        reasons = drop_reasons or {}
        for key, rec in self._nodes.items():
            if rec["drop_stage"] is not None:
                continue  # уже отвалился раньше — не трогаем
            if key in alive_keys:
                if rec["stage"] < idx:
                    rec["stage"] = idx
            else:
                if rec["stage"] < idx:
                    rec["drop_stage"] = stage
                    rec["drop_reason"] = reasons.get(key) or "—"

    # ------------------------------------------------------------------
    # Отчёты
    # ------------------------------------------------------------------
    def funnel_for_source(self, source: str) -> dict[str, int]:
        """Число узлов источника, вошедших в каждую стадию.

        funnel[stage] = «дожил до входа в стадию»: узел, отвалившийся на
        initial, засчитывается в quick/max_ping/initial и не дальше.
        """
        out = {name: 0 for name in STAGES}
        for rec in self._nodes.values():
            if rec["source"] != source:
                continue
            out["discovered"] += 1
            if rec["drop_stage"] is None:
                last_idx = rec["stage"]
            else:
                last_idx = _STAGE_IDX[rec["drop_stage"]]
            for i in range(1, last_idx + 1):
                out[STAGES[i]] += 1
        return out

    def lost_at(self, source: str) -> dict[str, dict[str, int]]:
        """По источнику: стадия → {причина: число} отвалившихся."""
        out: dict[str, dict[str, int]] = {}
        for rec in self._nodes.values():
            if rec["source"] != source or rec["drop_stage"] is None:
                continue
            stage = rec["drop_stage"]
            reason = str(rec["drop_reason"] or "—")
            bucket = out.setdefault(stage, {})
            bucket[reason] = bucket.get(reason, 0) + 1
        return out

    def report(self) -> dict[str, Any]:
        """Секция "trace" для report.json."""
        sources_out: list[dict[str, Any]] = []
        for src in self._source_order():
            funnel = self.funnel_for_source(src)
            lost = self.lost_at(src)
            sources_out.append({
                "source": src,
                "funnel": funnel,
                "lost_at": lost,
                "final": funnel.get("exported", 0),
            })
        # Судьба узлов, доживших до quick-пинга ИЛИ отвалившихся не раньше
        # max_ping: их сотни — можно точечно. Массовые потери на tcp-предфильтре
        # и quick-пинге (десятки тысяч) — только агрегатами по причинам.
        nodes_out: list[dict[str, Any]] = []
        for key, rec in self._nodes.items():
            stage_idx: int = rec["stage"]
            drop_idx = _STAGE_IDX[rec["drop_stage"]] if rec["drop_stage"] else None
            include = (drop_idx is None and stage_idx >= 1) or (drop_idx is not None and drop_idx >= 2)
            if not include:
                continue
            last = stage_idx if drop_idx is None else max(0, drop_idx - 1)
            nodes_out.append({
                "key": key,
                "source": rec["source"],
                "last_stage": STAGES[last],
                "dropped_at": rec["drop_stage"],
                "reason": rec["drop_reason"],
            })
        return {
            "enabled": True,
            "stages": list(STAGES),
            "checkpoints_done": list(self._checkpoints),
            "sources": sources_out,
            "nodes": nodes_out,
            "note": "воронка по источникам: сколько узлов дожило до каждой стадии; "
                    "lost_at — стадия и причина отвала; nodes — судьба узлов, "
                    "доживших до quick-пинга или отвалившихся не раньше max_ping",
        }

    def _source_order(self) -> list[str]:
        """Источники: по числу узлов (убыв.), неизвестный — последним."""
        def sort_key(src: str) -> tuple[int, int]:
            return (0 if src != _UNKNOWN else 1, -self._sources.get(src, 0))
        return sorted(self._sources, key=sort_key)

    # ------------------------------------------------------------------
    # Человекочитаемый лог
    # ------------------------------------------------------------------
    def write_log(self, path: Path, *, header: str = "") -> None:
        """Переписать trace.log целиком (текущее состояние воронки)."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            lines: list[str] = []
            lines.append("=" * 100)
            lines.append(f"ТРАССИРОВКА ПОДПИСОК (воронка потерь) — {time.strftime('%Y-%m-%d %H:%M:%S')}")
            if header:
                lines.append(header)
            lines.append("Стадии: " + " → ".join(STAGES))
            lines.append("=" * 100)
            total = len(self._nodes)
            alive_now = sum(1 for r in self._nodes.values() if r["drop_stage"] is None)
            lines.append(f"узлов зарегистрировано: {total}; живых на сейчас: {alive_now}")
            lines.append("")
            lines.append(
                f"{'источник':<70} {'обн':>5} " + " ".join(f"{s[:5]:>6}" for s in STAGES[1:])
            )
            lines.append("-" * 100)
            for src in self._source_order():
                funnel = self.funnel_for_source(src)
                cells = " ".join(f"{funnel[s]:>6}" for s in STAGES[1:])
                lines.append(f"{src[:70]:<70} {funnel['discovered']:>5} {cells}")
            # Причины отвала — только непустые, компактно
            any_lost = any(self.lost_at(src) for src in self._sources)
            if any_lost:
                lines.append("")
                lines.append("ГДЕ ОТВАЛИЛИСЬ (стадия: причина → число):")
                for src in self._source_order():
                    lost = self.lost_at(src)
                    if not lost:
                        continue
                    lines.append(f"  {src[:80]}")
                    for stage in STAGES:
                        reasons = lost.get(stage)
                        if not reasons:
                            continue
                        parts = ", ".join(
                            f"{r[:44]}×{n}" for r, n in sorted(reasons.items(), key=lambda kv: -kv[1])[:6]
                        )
                        lines.append(f"    {stage:<10} {parts}")
            # Точечные потери (узел → стадия → причина) для отвалов не раньше
            # max_ping: это «интересные» потери, их десятки-сотни.
            detail_drops: list[tuple[str, str, str, str]] = []
            for key, rec in self._nodes.items():
                if rec["drop_stage"] is None:
                    continue
                if _STAGE_IDX[rec["drop_stage"]] < 2:
                    continue
                detail_drops.append(
                    (rec["source"], key, rec["drop_stage"], str(rec["drop_reason"] or "—"))
                )
            if detail_drops:
                lines.append("")
                lines.append("ОТВАЛИЛИСЬ ПОСЛЕ QUICK-ПИНГА (узел → стадия → причина):")
                by_src: dict[str, list[tuple[str, str, str]]] = {}
                for src, key, stage, reason in detail_drops:
                    by_src.setdefault(src, []).append((key, stage, reason))
                for src in self._source_order():
                    drops = by_src.get(src)
                    if not drops:
                        continue
                    lines.append(f"  {src[:80]} ({len(drops)} узлов)")
                    for key, stage, reason in drops[:200]:
                        lines.append(f"    {key:<40} {stage:<10} {reason[:60]}")
                    if len(drops) > 200:
                        lines.append(f"    … и ещё {len(drops) - 200}")
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except Exception:
            # Трассировка не должна ломать конвейер ни при каких условиях.
            pass

    def summary_line(self, stage: str) -> str:
        """Однострочная сводка для основного лога после стадии."""
        total = len(self._nodes)
        alive = sum(1 for r in self._nodes.values() if r["drop_stage"] is None)
        dropped_here = sum(
            1 for r in self._nodes.values() if r["drop_stage"] == stage
        )
        return (
            f"[trace] {stage}: живых {alive} из {total} "
            f"(отвалилось на стадии: {dropped_here}) — детальная воронка: data/trace.log"
        )
