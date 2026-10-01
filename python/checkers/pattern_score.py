"""Pattern-based scoring + known-good filter для sub_generator и GHA.

v38: Вынесено из scripts/refresh_subs.py в общий модуль, чтобы ОБА
движка (sub_generator на ПК + GHA workflow) использовали ОДНУ реализацию.

Pattern scoring — замена xray-ping для сред, где xray-ping бесполезен
(GHA на Azure US, ПК на открытом интернете). Оценивает узлы по сходству
с known_good.txt (проверенными на мобилке конфигами):
  SNI exact match         +40
  SNI same TLD+1          +20
  Host /24 match           +30
  Host domain suffix       +25
  Protocol+security         +10
  Transport                 +5
  Flow                      +5
  Fingerprint               +5
  SNI real domain           +5
  Full stack bonus         +15 (все 4 компонента совпали)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Iterable

from runtime.types import XrayNode

# Кеш паттернов из known_good.txt.
_KG_PATTERNS: dict | None = None


def _kg_path_default() -> Path:
    """Дефолтный путь к known_good.txt относительно модуля."""
    return Path(__file__).resolve().parent.parent.parent / "data" / "known_good.txt"


def load_known_good_patterns(path: Path | None = None) -> dict:
    """Извлечь pattern features из known_good.txt.

    Возвращает dict:
      sni_set, sni_tld_set, ip_subnets, host_suffixes,
      proto_security, transports, flows, fingerprints, nodes
    """
    global _KG_PATTERNS
    if _KG_PATTERNS is not None:
        return _KG_PATTERNS

    if path is None:
        path = _kg_path_default()

    patterns: dict = {
        "sni_set": set(), "sni_tld_set": set(), "ip_subnets": set(),
        "host_suffixes": set(), "proto_security": set(), "transports": set(),
        "flows": set(), "fingerprints": set(), "nodes": [],
    }

    if not path or not path.is_file():
        _KG_PATTERNS = patterns
        return patterns

    # Ленивый импорт.
    repo_root = Path(__file__).resolve().parent.parent.parent
    if str(repo_root / "python") not in sys.path:
        sys.path.insert(0, str(repo_root / "python"))
    from runtime.parse import parse_node_link, _node_links_from_text

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        _KG_PATTERNS = patterns
        return patterns

    for url in _node_links_from_text(text):
        try:
            node = parse_node_link(url)
        except Exception:
            continue
        if not node:
            continue
        patterns["nodes"].append(node)

        sni = (node.query.get("sni") or node.query.get("host") or "").strip().lower()
        if sni:
            patterns["sni_set"].add(sni)
            parts = sni.split(".")
            if len(parts) >= 2:
                patterns["sni_tld_set"].add(".".join(parts[-2:]))

        host = (node.host or "").strip()
        try:
            import ipaddress
            ipaddress.IPv4Address(host)
            patterns["ip_subnets"].add(host)
        except (ValueError, TypeError):
            pass

        host_parts = host.split(".")
        if len(host_parts) >= 2:
            patterns["host_suffixes"].add(".".join(host_parts[-2:]))

        proto = (node.protocol or "").lower()
        security = (node.query.get("security") or "").lower()
        if proto and security:
            patterns["proto_security"].add(f"{proto}+{security}")

        transport = (node.query.get("type") or "").lower()
        if transport:
            patterns["transports"].add(transport)

        flow = (node.query.get("flow") or "").lower()
        if flow:
            patterns["flows"].add(flow)

        fp = (node.query.get("fp") or "").lower()
        if fp:
            patterns["fingerprints"].add(fp)

    _KG_PATTERNS = patterns
    return patterns


def reset_cache() -> None:
    """Сбросить кеш паттернов."""
    global _KG_PATTERNS
    _KG_PATTERNS = None


def pattern_score(node: XrayNode, patterns: dict) -> int:
    """Оценить узел по сходству с known_good. Возвращает 0-120+."""
    if not patterns or not patterns.get("nodes"):
        return 0

    score = 0
    sni_set = patterns.get("sni_set", set())
    sni_tld_set = patterns.get("sni_tld_set", set())
    ip_subnets = patterns.get("ip_subnets", set())
    host_suffixes = patterns.get("host_suffixes", set())
    proto_security = patterns.get("proto_security", set())
    transports = patterns.get("transports", set())
    flows = patterns.get("flows", set())
    fingerprints = patterns.get("fingerprints", set())

    # SNI
    sni = (node.query.get("sni") or node.query.get("host") or "").strip().lower()
    if sni:
        if sni in sni_set:
            score += 40
        else:
            parts = sni.split(".")
            if len(parts) >= 2:
                tld_plus1 = ".".join(parts[-2:])
                if tld_plus1 in sni_tld_set:
                    score += 20
            if "." in sni and len(sni) > 5:
                score += 5

    # Host /24 or domain suffix
    host = (node.host or "").strip()
    try:
        import ipaddress
        ipaddress.IPv4Address(host)
        for known_ip in ip_subnets:
            try:
                host_net = ipaddress.IPv4Network(f"{host}/24", strict=False)
                known_net = ipaddress.IPv4Network(f"{known_ip}/24", strict=False)
                if host_net == known_net:
                    score += 30
                    break
            except Exception:
                pass
    except (ValueError, TypeError):
        host_parts = host.split(".")
        if len(host_parts) >= 2:
            suffix = ".".join(host_parts[-2:])
            if suffix in host_suffixes:
                score += 25

    # Protocol + security
    proto = (node.protocol or "").lower()
    security = (node.query.get("security") or "").lower()
    if proto and security and f"{proto}+{security}" in proto_security:
        score += 10

    # Transport
    transport = (node.query.get("type") or "").lower()
    if transport and transport in transports:
        score += 5

    # Flow
    flow = (node.query.get("flow") or "").lower()
    if flow and flow in flows:
        score += 5

    # Fingerprint
    fp = (node.query.get("fp") or "").lower()
    if fp and fp in fingerprints:
        score += 5

    # Full stack bonus
    proto_sec_match = bool(proto and security and f"{proto}+{security}" in proto_security)
    transport_match = bool(transport and transport in transports)
    flow_match = bool(flow and flow in flows)
    fp_match = bool(fp and fp in fingerprints)
    if proto_sec_match and transport_match and flow_match and fp_match:
        score += 15

    return score


def apply_pattern_scoring(
    nodes: list[XrayNode],
    known_good_path: Path | None = None,
    *,
    min_score: int = 40,
    log_sink=None,
) -> list[XrayNode]:
    """Оценить + отфильтровать + отсортировать по score.

    Если known_good.txt нет — возвращает nodes как есть.
    """
    reset_cache()
    patterns = load_known_good_patterns(known_good_path)

    if not patterns.get("nodes"):
        if log_sink:
            log_sink("[sub] --pattern-score: known_good.txt empty/not found — skipping")
        return nodes

    if log_sink:
        log_sink(f"[sub] --pattern-score: loaded {len(patterns['nodes'])} verified configs")
        log_sink(f"[sub] --pattern-score: {len(patterns['sni_set'])} SNIs, "
                 f"{len(patterns['host_suffixes'])} host suffixes, "
                 f"{len(patterns['proto_security'])} proto+security combos")

    scored = [(n, pattern_score(n, patterns)) for n in nodes]
    scored.sort(key=lambda x: -x[1])

    above = [(n, s) for n, s in scored if s >= min_score]
    below_count = len(scored) - len(above)

    if log_sink:
        log_sink(f"[sub] --pattern-score: {len(nodes)} scored, "
                 f"{len(above)} above threshold ({min_score}), "
                 f"{below_count} below")
        if above:
            top_scores = [s for _, s in above[:5]]
            log_sink(f"[sub] --pattern-score: top 5 scores: {top_scores}")

    return [n for n, _ in above]


def load_known_good_nodes(path: Path | None = None) -> list[XrayNode]:
    """Загрузить known_good узлы для append в финальный список."""
    patterns = load_known_good_patterns(path)
    return list(patterns.get("nodes", []))


__all__ = [
    "apply_pattern_scoring",
    "load_known_good_nodes",
    "load_known_good_patterns",
    "pattern_score",
    "reset_cache",
]
