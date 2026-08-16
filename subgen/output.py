"""Запись результатов: подписки, рабочие конфиги, отчёты, кеш."""
from __future__ import annotations

import base64
import json

from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from subgen.config import SUBSCRIPTION_DESCRIPTION
from subgen.settings import get_description, get_prefix
from xray_runtime import XrayProbeResult


# Анти-детект ТСПУ (статья dpi-tls-june-2026, схема «Siberian»): лояльные
# uTLS-фингерпринты. chrome/ios/safari/randomized — палевные сигналы для
# Сигнала 2 «заморозки». При записи подписки подменяем их на лояльный.
_LOYAAL_FINGERPRINTS = {"firefox", "edge", "360", "qq"}
_SAFE_DEFAULT_FINGERPRINT = "firefox"


def _harden_url(raw_url: str) -> str:
    """Переписать URL узла: гарантировать лояльный uTLS-фингерпринт.

    Для vless/trojan с TLS/REALITY подменяет палевный/отсутствующий ``fp``
    на лояльный (firefox), чтобы конфиг в выходной подписке не совпадал с
    сигнатурой, по которой ТСПУ детектит «подозрительный» клиент. Креды,
    SNI, путь и фрагмент (имя) не трогаются.
    """
    url = str(raw_url or "").strip()
    if not url:
        return url
    lowered = url.lower()
    if not (lowered.startswith("vless://") or lowered.startswith("trojan://")):
        return url
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    query = parse_qs(parsed.query, keep_blank_values=True)
    security = (query.get("security") or [""])[0].lower()
    if security and security not in ("tls", "reality"):
        return url
    fp = (query.get("fp") or query.get("fingerprint") or [""])[0].strip().lower()
    if not fp or fp not in _LOYAAL_FINGERPRINTS:
        query["fp"] = [_SAFE_DEFAULT_FINGERPRINT]
        query.pop("fingerprint", None)
    new_query = urlencode(
        [(key, value) for key, values in query.items() for value in values],
        safe="/@:",
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def write_file(path: Path, content: str) -> None:

    """Атомарная запись текста (tmp + replace), создаёт каталоги."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def append_text(path: Path, text: str) -> None:
    """Дописать строки в файл (для инкрементального сохранения узлов)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()


def urls_text(items: Iterable[XrayProbeResult]) -> str:
    """Список узлов -> построчный текст (с завершающим переносом строки).

    URL узлов харднятся анти-детектом (_harden_url), чтобы в подписку
    попадали только лояльные для ТСПУ параметры.
    """
    text = "\n".join(_harden_url(w.node.raw_url) for w in items)
    if text:
        text += "\n"
    return text


def build_subscription(rows: list[dict[str, Any]]) -> str:
    """Собрать текст подписки из строк отчёта (url по строкам + описание + префикс).

    Префикс добавляется первой строкой, затем описание, затем сами конфиги.
    URL каждого узла пропускается через анти-детект-харденинг (_harden_url):
    гарантируется лояльный uTLS-фингерпринт (fp=firefox), чтобы конфиг не
    совпадал с сигнатурой, по которой ТСПУ детектит подозрительный клиент.
    """
    urls = [_harden_url(str(row["url"])) for row in rows]
    text = "\n".join(urls)

    if text:
        text += "\n"
    prefix = get_prefix().strip()
    description = get_description()
    header = ""
    if prefix:
        header += prefix + "\n"
    header += description
    return header + text



def write_subscription_files(
    rows: list[dict[str, Any]],
    *,
    working_path: Path,
    out_path: Path,
    plain: bool,
) -> str:
    """Записать working (текст) и out (base64 или текст) файлы подписки.

    Возвращает итоговое содержимое out-файла.
    """
    subscription_text = build_subscription(rows)
    if not plain:
        subscription_b64 = base64.b64encode(subscription_text.encode("utf-8")).decode("ascii")
    else:
        subscription_b64 = subscription_text
    write_file(working_path, subscription_text)
    write_file(out_path, subscription_b64)
    return subscription_b64


def write_report(report_path: Path, report: dict[str, Any]) -> None:
    write_file(report_path, json.dumps(report, ensure_ascii=False, indent=2))


def write_geo_cache(geo_cache_path: Path, geo_cache: dict[str, tuple[str, str]]) -> None:
    geo_cache_json = {key: list(value) for key, value in geo_cache.items()}
    write_file(geo_cache_path, json.dumps(geo_cache_json, ensure_ascii=False, indent=2))
