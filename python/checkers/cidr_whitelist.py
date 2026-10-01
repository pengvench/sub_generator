"""Проверка IP-адреса узла против community CIDR whitelist (BS-CIDR).

Что это и зачем:
  TSPU (Технические средства противодействия угрозам) на мобильных сетях РФ
  реально применяет ДВА фильтра одновременно:
    1. SNI-проверка — SNI в TLS ClientHello должен быть в БЕЛОМ списке
       (sberbank.ru, vk.com, github.com, ...). См. sni_category.py.
    2. IP-проверка — destination IP (это IP прокси-сервера) должен быть в
       CIDR-списке разрешённых подсетей. Это значит: даже если SNI идеальный,
       но IP сервера не в whitelist'е — ТСПУ всё равно блокирует.

  hxehex/russia-mobile-internet-whitelist отдаёт ТРИ файла:
    whitelist.txt     — ~910 SNI-доменов (используется в sni_category.py).
    cidrwhitelist.txt — ~30 000 CIDR-подсетей (этот модуль).
    ipwhitelist.txt   — ~141 000 отдельных IP (избыточно, не используется).

  Этот модуль НЕ запускает xray — это чистая статическая проверка IP узла
  против списка CIDR'ов через ipaddress.IPv4Network. Работает на Linux/Windows,
  в GHA и в основном приложении.

Использование:
  from checkers.cidr_whitelist import is_ip_in_whitelist, load_cidr_whitelist
  if is_ip_in_whitelist(node.host):
      # IP узла в BS-CIDR — проходит IP-фильтр TSPU.
  else:
      # IP не в whitelist'е — даже при идеальном SNI будет блок на мобильной сети.

Синк списка: scripts/sync_sni_whitelist.py --with-cidr → data/cidr_whitelist.txt.

Лимиты:
  - Только IPv4 (IPv6 в РФ mobile не используется — операторы не invested).
  - Список community-curated, обновляется людьми во время блокировок —
    может быть не полным, но это лучший публичный источник.
  - Проверка статическая: не проверяет, реально ли TSPU блокирует. Только
    «должен ли пройти по SNI+IP whitelist'у». Реальный TSPU может быть строже.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path
from typing import Iterable

from runtime.types import XrayNode

_logger = logging.getLogger(__name__)

# Кеш распарсенных IPv4Network — чтобы не парсить 30k CIDR на каждый узел.
# Инвалидация через reset_cache() — например, после sync_sni_whitelist.py.
_CACHED_NETWORKS: list[ipaddress.IPv4Network] | None = None

# Пути к CIDR-whitelist файлу — те же 3 варианта, что и в sni_category.py:
#   1. env var CIDR_WHITELIST_FILE (для GHA/CI);
#   2. data/cidr_whitelist.txt относительно корня репо;
#   3. data/cidr_whitelist.txt относительно cwd.
def _cidr_whitelist_paths() -> list[Path]:
    return [
        Path(os.environ.get("CIDR_WHITELIST_FILE", "")),
        Path(__file__).resolve().parent.parent.parent / "data" / "cidr_whitelist.txt",
        Path.cwd() / "data" / "cidr_whitelist.txt",
    ]


def _parse_cidr_line(line: str) -> ipaddress.IPv4Network | None:
    """Распарсить одну строку CIDR. Возвращает None для мусора/комментариев."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Срезаем порт, если вдруг «2.63.0.0/17:443».
    if line.count(":") == 1:
        line = line.split(":", 1)[0]
    try:
        # strict=False: принимаем host-bits (например, 2.63.5.0/17 — это ОК,
        # значит «2.63.0.0/17» после маски). Community list иногда так пишет.
        return ipaddress.IPv4Network(line, strict=False)
    except (ValueError, TypeError):
        return None


def load_cidr_whitelist() -> list[ipaddress.IPv4Network]:
    """Загрузить CIDR whitelist из data/cidr_whitelist.txt (если есть).

    Возвращает кешированный список IPv4Network. Если файла нет (например,
    запустили без sync_sni_whitelist.py --with-cidr) — возвращает пустой
    список (тогда is_ip_in_whitelist всегда False, фильтр не работает).
    """
    global _CACHED_NETWORKS
    if _CACHED_NETWORKS is not None:
        return _CACHED_NETWORKS
    networks: list[ipaddress.IPv4Network] = []
    for path in _cidr_whitelist_paths():
        try:
            if not path or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                net = _parse_cidr_line(line)
                if net is not None:
                    networks.append(net)
            # Если нашли файл — выходим (не пробуем остальные пути).
            break
        except Exception as exc:
            _logger.debug("cidr_whitelist: не прочитан %s: %s", path, exc)
            continue
    _CACHED_NETWORKS = networks
    return networks


def reset_cache() -> None:
    """Сбросить кеш CIDR whitelist (для тестов / после sync_sni_whitelist.py)."""
    global _CACHED_NETWORKS
    _CACHED_NETWORKS = None


def is_ip_in_whitelist(host: str) -> bool:
    """IP-адрес узла входит в BS-CIDR whitelist?

    Возвращает True если:
      - host — IPv4 (парсится ipaddress.IPv4Address);
      - host входит хотя бы в одну из CIDR-подсетей в whitelist'е.
    Возвращает False если:
      - host — доменное имя (не IP);
      - host — IPv6;
      - whitelist пуст (файл не выкачан);
      - IP не входит ни в одну подсеть.
    """
    networks = load_cidr_whitelist()
    if not networks:
        return False  # whitelist не загружен — не можем гарантировать проход
    host = (host or "").strip()
    if not host:
        return False
    # Парсим как IPv4 (DNS-имена НЕ парсим — это работа TSPU делать DNS-resolve).
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        return False  # это домен, не IP — фильтр CIDR неприменим
    for net in networks:
        if ip in net:
            return True
    return False


def node_ip_status(node: XrayNode) -> str:
    """Категория IP-адреса узла относительно BS-CIDR whitelist.

    Returns:
      "whitelisted" — host это IPv4, входит в BS-CIDR. Идеально для TSPU.
      "ip_not_whitelisted" — host это IPv4, но НЕ входит в BS-CIDR. Узел
                              может работать на открытом интернете, но на
                              мобильной сети РФ ТСПУ скорее всего заблокирует.
      "domain" — host это доменное имя. Проверку CIDR сделать нельзя —
                 TSPU сделает DNS-resolve сам (и заблокирует, если IP не в BS).
      "empty" — host пустой или None.
    """
    host = (node.host or "").strip()
    if not host:
        return "empty"
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return "domain"
    return "whitelisted" if is_ip_in_whitelist(host) else "ip_not_whitelisted"


def tspu_strict_passes(node: XrayNode, *, sni_check: bool = True,
                       cidr_check: bool = False,
                       allow_grey: bool = True,
                       allow_fake: bool = False) -> tuple[bool, str]:
    """Пройти ли узел TSPU-эмулятор.

    v36: cidr_check ПО УМОЛЧАНИЮ False. Причина: GHA на Azure US/EU —
    открытый интернет. Проверка IP-CIDR убивает ВСЕ зарубежные VPN-серверы
    (их IP не в BS-CIDR, но они работают на мобилке через CDN/туннели).
    TSPU на мобилке проверяет SNI (блокирует instagram/chatgpt), но IP-CIDR
    проверяет ТОЛЬКО при полном blackout'е (когда whitelist'en весь интернет).
    Для обычного ограниченного режима — SNI blacklist достаточно.

    Что фильтруем по умолчанию (cidr_check=False):
      - SNI в ЧС (instagram.com, chatgpt.com ...) → FAIL
      - SNI пустой/фейк → FAIL
      - Всё остальное → PASS (серый/белый SNI + любой IP)

    Что фильтруем в strict режиме (cidr_check=True):
      - + IP в BS-CIDR whitelist → только для полного blackout'а
    """
    # 1. SNI-проверка.
    if sni_check:
        # Ленивый импорт, чтоб не тащить sni_category в случае выключенной SNI-проверки.
        from checkers.sni_category import passes_filter as _bs_passes, sni_category as _sni_cat
        cat = _sni_cat(node)
        if cat == "black":
            return False, "sni_blacklisted"
        if cat == "none":
            return False, "sni_empty"
        if cat == "fake" and not allow_fake:
            return False, "sni_fake"
        if cat == "grey" and not allow_grey:
            return False, "sni_grey"
        # cat == "white" — проходит. cat in {"fake","grey"} с разрешением — проходит.

    # 2. IP-проверка (CIDR).
    if cidr_check:
        ip_status = node_ip_status(node)
        if ip_status == "empty":
            return False, "ip_empty"
        if ip_status == "domain":
            # v34: ДО fixed — FAIL "ip_domain_unresolved" → отбраковывал ВСЕ
            # конфиги с доменным host'ом (а это 90%+ паблик-подписок, где host
            # = test.realhost.com, а не IP). TSPU на мобиле делает DNS-resolve
            # САМ — если домен резолвится в whitelisted IP, пропустит.
            # Мы не можем DNS-resolve'нуть без запущенного xray (это статичная
            # проверка), поэтому SKIP — не отбраковываем. Узел проверится
            # на следующих стадиях (TCP-ping → TLS-handshake через SOCKS в
            # full_test режиме).
            # Если хотите strict — передайте --tspu-sim-no-domain-skip.
            pass  # skip CIDR check for domain hosts
        elif ip_status == "ip_not_whitelisted":
            return False, "ip_not_whitelisted"
        # ip_status == "whitelisted" — проходит.

    return True, "whitelisted"


def tspu_summary(nodes: Iterable[XrayNode]) -> dict[str, int]:
    """Сводка verdict'ов tspu_strict_passes по списку узлов."""
    summary: dict[str, int] = {}
    for n in nodes:
        _, reason = tspu_strict_passes(n)
        summary[reason] = summary.get(reason, 0) + 1
    return summary


__all__ = [
    "is_ip_in_whitelist",
    "load_cidr_whitelist",
    "node_ip_status",
    "reset_cache",
    "tspu_strict_passes",
    "tspu_summary",
]
