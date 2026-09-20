"""Фильтр конфигов по параметрам протокола (vless reality xhttp и т.п.).

Запрос пользователя: «хочу vless reality xhttp» — но список возможных
комбинаций заранее не знает никто. Решение: фильтр по 4 независимым
измерениям, каждое — «белый список» значений (галочки в UI / CSV в CLI):

- ``protocol``  — vless / vmess / trojan / shadowsocks / hysteria2 /
                   hysteria (v1) — ВСЕ протоколы, которые умеет парсер
                   (runtime/uritools.py:NODE_SCHEMES), ничего не вырезается;
- ``security``  — none / tls / reality (+ «прочие»);
- ``transport`` — tcp / ws / grpc / xhttp / splithttp / httpupgrade /
                   http(h2) / kcp / quic (+ «прочие»);
- ``flow``      — none / vision (xtls-rprx-vision) (+ «прочие»).

Значения нормализуются ровно по той же логике, которой конвертер конфигов
(runtime/configs.py) строит streamSettings — иначе фильтр отберёт «vless
xhttp», а конвертер это не поднимет (или наоборот). Неизвестное значение
(новый транспорт, о котором фильтр не знает) попадает в корзину «other» —
галочка «Прочие/неизвестные» в UI: список конфигураций открытый, предусмотреть
всё нельзя, «прочее» не теряется молча.

Применяется СРАЗУ после загрузки подписок (до распинговки): если юзер хочет
только vless+reality+xhttp, гонять TCP-пинг по 17к vmess-нод — часы впустую.
Работает и при перепроверке с этапа (кеш рабочих конфигов прогоняется через
тот же матчер).
"""
from __future__ import annotations

from typing import Any, Callable

# ---------------------------------------------------------------------------
# Канонические измерения и их значения (для UI-галочек и валидации CLI).
# Порядок значений = порядок галочек в UI.
# ---------------------------------------------------------------------------
DIMENSIONS: dict[str, tuple[str, ...]] = {
    # Полный список протоколов, которые ПРОВЕРЯЕМ (парсер их поднимает):
    # vless/vmess/trojan (xray) + shadowsocks (оба ядра) + hysteria2/hysteria
    # (sing-box). Список открытый: неизвестный протокол -> корзина «other».
    "protocol": ("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria"),
    "security": ("none", "tls", "reality"),
    "transport": ("tcp", "ws", "grpc", "xhttp", "splithttp", "httpupgrade", "http", "kcp", "quic"),
    "flow": ("none", "vision"),
}

# ---------------------------------------------------------------------------
# v14: «Самые ходовые» — пометки популярности (просьба юзера: полный список
# протоколов с галочками + приписка, что сейчас в ходу). Это ТОЛЬКО метка в
# UI (★ + тултип с пояснением): фильтр ничего не вырезает и не пресетует —
# разнообразие остаётся, юзер сам снимает/ставит галочки.
# Ориентир — практика РФ-обхода на осень 2026 + TL;DR статьи Amnezia
# («Рабочий ВПН»: Shadowsocks и masquerade-под-HTTPS — то, что держит волны).
# ---------------------------------------------------------------------------
POPULAR: dict[str, frozenset[str]] = {
    "protocol": frozenset({"vless", "hysteria2", "shadowsocks"}),
    "security": frozenset({"reality"}),
    "transport": frozenset({"tcp", "ws", "grpc"}),
    "flow": frozenset({"vision"}),
}

# Короткое пояснение «почему ходовой» для тултипа галочки (UI).
POPULAR_NOTES: dict[str, str] = {
    "vless": (
        "Самый массовый протокол РФ-обхода: лёгкий, без лишнего шифрования, "
        "пара к нему — reality и vision."
    ),
    "hysteria2": (
        "QUIC-протокол, очень популярен на плохих сетях и мобильных: "
        "выдерживает потери лучше TCP-транспорта."
    ),
    "shadowsocks": (
        "Классика, живёт вечно: ss-2022 устойчив к активным пробам DPI — "
        "один из TL;DR-рекомендаций статьи Amnezia."
    ),
    "reality": (
        "Самая ходовая маскировка: выглядит как TLS к настоящему сайту, "
        "не даёт себя отличить активными пробами."
    ),
    "tcp": (
        "Базовый транспорт; связка vless + reality + vision поверх TCP — "
        "сейчас самая массовая."
    ),
    "ws": (
        "Стандарт за CDN (Cloudflare): трафик выглядит как обычный веб-сокет "
        "к CDN-домену."
    ),
    "grpc": (
        "Мультиплексированный HTTP/2-транспорт — популярная пара к "
        "vless + tls."
    ),
    "vision": (
        "xtls-rprx-vision — стандарт для vless + reality + tcp: убирает "
        "двойное шифрование, не палится DPI."
    ),
}

# Псевдо-значение для неизвестных параметров (открытый список конфигураций).
OTHER = "other"

# Человекочитаемые подписи для UI (значение -> ярлык галочки).
LABELS: dict[str, str] = {
    "shadowsocks": "ss",
    "hysteria": "hysteria (v1)",
    "http": "http (h2)",
    "none": "без TLS",
    "vision": "xtls-rprx-vision",
    OTHER: "Прочие/неизв.",
}

# Синонимы, схлопываемые при нормализации (как в runtime/configs.py).
_TRANSPORT_ALIASES = {
    "h2": "http",
    "h2c": "http",
    "raw": "tcp",
    "websocket": "ws",
    "gun": "grpc",
}
_SECURITY_ALIASES = {
    "": "none",
    "auto": "none",   # vmess tls=auto — фактически без TLS-настроек
    "xtls": "tls",    # устаревший security=xtls (vless до reality)
}
_FLOW_ALIASES = {
    "": "none",
    "none": "none",
    "xtls-rprx-vision": "vision",
    "xtls-rprx-vision-udp443": "vision",
}


def _canon(value: object, aliases: dict[str, str], known: tuple[str, ...]) -> str:
    """Нормализация одного параметра: lower -> синоним -> known/other."""
    text = str(value or "").strip().lower()
    text = aliases.get(text, text)
    if text in known or text == OTHER:
        return text
    return OTHER


def node_params(node: Any) -> dict[str, str]:
    """Извлечь нормализованные параметры узла (protocol/security/transport/flow).

    Логика зеркальна runtime/configs.py:``_xray_stream_settings`` —
    ``type``/``network``/``net`` для транспорта, ``security``/``tls`` для
    шифрования, ``h2``→``http``. Протоколы sing-box (hysteria/hysteria2)
    всегда QUIC+TLS — транспортом считается ``quic``, security ``tls``.
    v14: hysteria (v1) и hysteria2 — РАЗНЫЕ значения фильтра (раньше
    сливались в одну корзину; юзер просил полный список протоколов).
    """
    protocol = str(getattr(node, "protocol", "") or "").strip().lower()
    if protocol == "hy2":
        protocol = "hysteria2"
    query = getattr(node, "query", None) or {}

    def q(*names: str) -> str:
        for name in names:
            value = query.get(name)
            if value:
                return str(value)
        return ""

    if protocol in ("hysteria", "hysteria2"):
        return {
            "protocol": protocol,
            "security": "tls",
            "transport": "quic",
            "flow": "none",
        }

    transport = _canon(q("type", "network", "net") or "tcp", _TRANSPORT_ALIASES, DIMENSIONS["transport"])
    security = _canon(q("security", "tls"), _SECURITY_ALIASES, DIMENSIONS["security"])
    flow = _canon(q("flow"), _FLOW_ALIASES, ("none", "vision"))
    return {"protocol": protocol, "security": security, "transport": transport, "flow": flow}


ParamsMatcher = Callable[[Any], bool]


def build_matcher(
    *,
    protocols: set[str] | None = None,
    security: set[str] | None = None,
    transports: set[str] | None = None,
    flows: set[str] | None = None,
) -> ParamsMatcher:
    """Собрать предикат «узел проходит фильтр параметров».

    ``None`` или пустое множество = измерение не фильтруется (пропускаем всё).
    Значения сравниваются после нормализации (node_params); спец-значение
    ``other`` покрывает неизвестные параметры. Спец-множество ``{"*"}`` =
    пропускать всё (для UI, где «все галочки сняты» трактуется как «без
    фильтра», а не «отсеять вообще всё» — один клик не должен обнулять
    результат).

    Активные наборы кладутся атрибутом ``_active`` на предикат — по ним
    apply_params_filter считает причину отвала (какое измерение не совпало).
    """
    dims = {
        "protocol": protocols,
        "security": security,
        "transport": transports,
        "flow": flows,
    }
    active: dict[str, set[str]] = {}
    for name, values in dims.items():
        if not values:
            continue
        cleaned = {str(v).strip().lower() for v in values if str(v).strip()}
        if cleaned and cleaned != {"*"}:
            active[name] = cleaned

    def _match(node: Any) -> bool:
        params = node_params(node)
        return all(params.get(name, OTHER) in allowed for name, allowed in active.items())

    _match._active = active  # type: ignore[attr-defined]
    return _match


def parse_csv_spec(value: object) -> set[str] | None:
    """Разобрать CSV-спецификацию CLI («vless,trojan» → {'vless','trojan'}).

    Пусто/None → None (измерение не фильтруется).
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return {part.strip().lower() for part in text.split(",") if part.strip()}


def apply_params_filter(
    working: list[Any],
    matcher: ParamsMatcher,
    *,
    log: Any = None,
) -> tuple[list[Any], dict[str, int]]:
    """Применить фильтр к списку узлов.

    Возвращает (оставшиеся узлы, счётчик отсеянных по измерениям). Причина
    отвала — первое несовпавшее измерение: счётчик нужен для честного лога
    «почему ушли N нод», а не только «сколько ушло». Узлы без .node
    (мусорные элементы) пропускаются как есть — фильтр по параметрам не
    должен ронять конвейер на чужом формате.
    """
    if not working:
        return list(working or []), {}
    active = getattr(matcher, "_active", None) or {}
    kept: list[Any] = []
    dropped: dict[str, int] = {}
    for w in working:
        # Элементы конвейера — обёртки с .node (XrayProbeResult); «голые»
        # XrayNode (список нод) тоже поддерживаем: у них есть protocol/query.
        node = getattr(w, "node", None)
        if node is None and hasattr(w, "protocol"):
            node = w
        if node is None:
            kept.append(w)
            continue
        params = node_params(node)
        reason: str | None = None
        for name, allowed in active.items():
            if params.get(name, OTHER) not in allowed:
                reason = name
                break
        if reason is None:
            kept.append(w)
        else:
            dropped[reason] = dropped.get(reason, 0) + 1
    return kept, dropped
