"""Предварительная локальная диагностика сети перед запуском проверок узлов.

ЕДИНСТВЕННАЯ реализация локальной диагностики: используется и конвейером
(subgen/pipeline.py — preflight перед тестированием узлов), и GUI-страницей
«Диагностика» (ui/pages/diag_page.py). Раньше GUI держал собственные inline-
проверки (дубль кода) — теперь обе точки сходятся на run_network_diagnostic().

Мотивация (из Karing NetCheckScreen): если локальный DNS заблокирован, до узла
или хоста невозможно подключиться в принципе. Поэтому перед тем как гонять
конфиги xray/sing-box, проверяем базовую сеть САМОСТОЯТЕЛЬНО, без участия
прокси:

1. Системный UDP DNS — прямой запрос A-записи к публичным резолверам.
   Дополнительно: DNS-fallback — если все UDP-серверы недоступны, пробуем
   следующий сервер по списку (9.9.9.9/AdGuard DNS), чтобы отличать «DNS
   полностью мёртв» от «доступен через резерв». UDP приоритетен: он чаще
   отвечает на заблокированных сетях, чем DoH/DoT.
2. DNS-over-HTTPS — HTTPS-запрос к cloudflare-dns.com/dns-query.
   Fallback: dns.google, dns.adguard-dns.com, doh.opendns.com.
3. Базовая HTTP/HTTPS-доступность — лёгкий GET generate_204.
4. Доступность заблокированных в РФ целей: chatgpt.com, instagram.com,
   api.telegram.org — факультативно (include_blocked_media=True). Это не
   влияет на internet_ok, но позволяет зафиксировать, что режет провайдер.

TUN-проверки УДАЛЕНЫ (v1.3): TUN-функциональность не используется в
ПК-версии, информация о TUN-адаптерах была бессмысленной.

Функции из checkers.resilience (udp_dns_check, dns_over_https_check) здесь
НЕ используются: они проверяют DNS ЧЕРЕЗ SOCKS-прокси поднятого узла, а нам
нужно проверить саму локальную сеть до запуска узлов.
"""
from __future__ import annotations

import contextlib
import socket
import time
from dataclasses import dataclass, field


UDP_DNS_SERVERS = [
    # Основные серверы — пробуются первыми.
    ("1.1.1.1", 53),     # Cloudflare
    ("8.8.8.8", 53),     # Google
    ("8.8.4.4", 53),     # Google alt
    ("9.9.9.9", 53),     # Quad9
    # Fallback-серверы — пробуются, если основные недоступны. UDP приоритетен:
    # на заблокированных сетях DoH/DoT часто режутся провайдером, а UDP DNS
    # отвечает. AdGuard и OpenDNS добавляют географическое разнообразие.
    ("94.140.14.14", 53),    # AdGuard DNS
    ("94.140.15.15", 53),    # AdGuard DNS alt
    ("208.67.222.222", 53),  # OpenDNS
    ("208.67.220.220", 53),  # OpenDNS alt
]

DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    # DoH-fallback: если Cloudflare/Google DoH блокированы на сети,
    # пробуем альтернативные провайдеров.
    "https://dns.adguard-dns.com/dns-query",
    "https://doh.opendns.com/dns-query",
]

# HTTP-проверки через generate_204. Google первым — он стабильно работает
# даже на заблокированных сетях (gstatic.com не режется DPI РФ).
# Cloudflare — fallback (на некоторых сетях cp.cloudflare.com блокируется).
HTTP_PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://connectivitycheck.gstatic.com/generate_204",
]

DNS_PROBE_DOMAIN = "google.com"

# Заблокированные в РФ цели. Проверка факультативна — она не влияет на
# internet_ok, но позволяет отличить «сеть пропускает блокировки» от
# «провайдер режет SNI». api.telegram.org добавлен для страницы
# «Диагностика» в GUI (Telegram — главный критерий пользователя).
BLOCKED_MEDIA_HTTP_PROBES = [
    # chatgpt.com — главное зеркало ChatGPT, часто блокируется по SNI/IP.
    ("chatgpt.com", "https://chatgpt.com/"),
    # chat.openai.com — legacy-домен, иногда блокируется отдельно.
    ("chat.openai.com", "https://chat.openai.com/"),
    # instagram.com — главный домен Instagram.
    ("instagram.com", "https://www.instagram.com/"),
    # api.telegram.org — Bot API Telegram (заблокирован на части сетей РФ).
    ("api.telegram.org", "https://api.telegram.org/"),
]


@dataclass
class NetworkDiagnosticResult:
    udp_dns_ok: bool = False
    udp_dns_latency_ms: float | None = None
    udp_dns_server: str | None = None
    doh_ok: bool = False
    doh_latency_ms: float | None = None
    doh_endpoint: str | None = None
    http_ok: bool = False
    http_latency_ms: float | None = None
    http_url: str | None = None
    # DNS-fallback: True, если первый сервер (1.1.1.1) НЕ ответил, но
    # один из резервных (9.9.9.9/AdGuard/OpenDNS) — ответил. Полезный
    # сигнал для диагностики: «основной DNS режется, но запасной работает».
    dns_fallback_used: bool = False
    dns_fallback_server: str | None = None
    # Детальные результаты по блокированным целям (include_blocked_media):
    # host -> {"ok": bool, "latency_ms": float | None, "status": int}.
    blocked_targets: dict[str, dict[str, object]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    # ------------------------------------------------------------- derived
    @property
    def chatgpt_ok(self) -> bool:
        """True, если доступен любой chatgpt/openai-домен."""
        return any(
            ("chatgpt" in host or "openai" in host) and bool(v.get("ok"))
            for host, v in self.blocked_targets.items()
        )

    @property
    def instagram_ok(self) -> bool:
        return any(
            "instagram" in host and bool(v.get("ok"))
            for host, v in self.blocked_targets.items()
        )

    @property
    def telegram_api_ok(self) -> bool:
        return any(
            host == "api.telegram.org" and bool(v.get("ok"))
            for host, v in self.blocked_targets.items()
        )

    @property
    def dns_ok(self) -> bool:
        """True, если хотя бы один способ резолва работает."""
        return self.udp_dns_ok or self.doh_ok

    @property
    def internet_ok(self) -> bool:
        """True, если есть DNS и базовая HTTPS-доступность."""
        return self.dns_ok and self.http_ok

    def as_dict(self) -> dict:
        return {
            "udp_dns_ok": self.udp_dns_ok,
            "udp_dns_latency_ms": self.udp_dns_latency_ms,
            "udp_dns_server": self.udp_dns_server,
            "doh_ok": self.doh_ok,
            "doh_latency_ms": self.doh_latency_ms,
            "doh_endpoint": self.doh_endpoint,
            "http_ok": self.http_ok,
            "http_latency_ms": self.http_latency_ms,
            "http_url": self.http_url,
            "dns_fallback_used": self.dns_fallback_used,
            "dns_fallback_server": self.dns_fallback_server,
            "chatgpt_ok": self.chatgpt_ok,
            "instagram_ok": self.instagram_ok,
            "telegram_api_ok": self.telegram_api_ok,
            "blocked_targets": {
                host: dict(v) for host, v in self.blocked_targets.items()
            },
            "errors": list(self.errors),
        }


def _build_dns_query(domain: str) -> bytes:
    """Собирает минимальный DNS-запрос A-записи."""
    transaction_id = b"\x12\x34"
    flags = b"\x01\x00"
    questions = b"\x00\x01"
    query_name = b""
    for part in domain.split("."):
        query_name += bytes([len(part)]) + part.encode("ascii")
    query_name += b"\x00"
    query_type = b"\x00\x01"
    query_class = b"\x00\x01"
    return (
        transaction_id + flags + questions
        + b"\x00\x00" * 3
        + query_name + query_type + query_class
    )


def local_udp_dns_check_with_fallback(
    domain: str = DNS_PROBE_DOMAIN,
    timeout: float = 2.0,
) -> tuple[bool, float | None, str | None, bool, str | None, str]:
    """UDP DNS-проверка с явным отслеживанием fallback-серверов.

    Перебирает серверы по порядку: сначала основные (1.1.1.1/8.8.8.8/8.8.4.4/
    9.9.9.9), потом fallback (AdGuard/OpenDNS). Возвращает первый успешный.

    UDP приоритетен над DoH: на заблокированных сетях DoH/DoT часто режутся
    провайдером (троттлинг 4-9 сек или дроп), а UDP DNS на 53-м порту
    обычно отвечает.

    Возвращает (ok, latency_ms, server, fallback_used, fallback_server, last_error).
    """
    query = _build_dns_query(domain)
    primary_servers = UDP_DNS_SERVERS[:4]
    fallback_servers = UDP_DNS_SERVERS[4:]
    last_error = ""
    fallback_server: str | None = None

    for dns_host, dns_port in primary_servers:
        sock = None
        started = time.perf_counter()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (dns_host, dns_port))
            response, _ = sock.recvfrom(512)
            if len(response) >= 12 and response[:2] == query[:2]:
                latency_ms = (time.perf_counter() - started) * 1000.0
                return True, latency_ms, f"{dns_host}:{dns_port}", False, None, ""
            last_error = f"empty or mismatched response from {dns_host}"
        except Exception as exc:
            last_error = f"{dns_host}: {type(exc).__name__}: {exc}"
        finally:
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()

    # Основные не ответили — пробуем fallback (AdGuard/OpenDNS).
    for dns_host, dns_port in fallback_servers:
        sock = None
        started = time.perf_counter()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (dns_host, dns_port))
            response, _ = sock.recvfrom(512)
            if len(response) >= 12 and response[:2] == query[:2]:
                latency_ms = (time.perf_counter() - started) * 1000.0
                fallback_server = f"{dns_host}:{dns_port}"
                return True, latency_ms, fallback_server, True, fallback_server, ""
            last_error = f"empty or mismatched response from {dns_host}"
        except Exception as exc:
            last_error = f"{dns_host}: {type(exc).__name__}: {exc}"
        finally:
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()

    return False, None, None, False, None, last_error


def local_doh_check(
    domain: str = DNS_PROBE_DOMAIN,
    timeout: float = 4.0,
) -> tuple[bool, float | None, str | None, str]:
    """HTTPS DoH-запрос, без участия SOCKS-прокси и системного hosts.

    Запрос идёт через checkers.hostres.direct_https_get: домен эндпоинта
    (cloudflare-dns.com / dns.google / ...) резолвится по DoH на
    IP-literal-серверы (1.1.1.1/8.8.8.8), соединение открывается на IP с
    SNI — записи hosts (в т.ч. подмены «разблокирующих» утилит) не влияют
    на диагностику. Перебирает DOH_ENDPOINTS по порядку: сначала
    Cloudflare/Google, затем AdGuard/OpenDNS как fallback.
    """
    last_error = ""
    for endpoint in DOH_ENDPOINTS:
        url = f"{endpoint}?name={domain}&type=A"
        started = time.perf_counter()
        try:
            from checkers.hostres import direct_https_get

            response = direct_https_get(
                url,
                timeout=timeout,
                max_bytes=2048,
                headers={
                    "Accept": "application/dns-json",
                    "User-Agent": "SubGenerator/1.0",
                },
            )
            if response.ok and response.status == 200 and response.body:
                latency_ms = (time.perf_counter() - started) * 1000.0
                return True, latency_ms, endpoint, ""
            last_error = f"{endpoint}: bad status or empty body"
        except Exception as exc:
            last_error = f"{endpoint}: {type(exc).__name__}: {exc}"
    return False, None, None, last_error


def local_http_check(
    timeout: float = 4.0,
) -> tuple[bool, float | None, str | None, str]:
    """Базовая HTTPS-доступность через лёгкие generate_204 URL (мимо hosts).

    Запросы идут через checkers.hostres.direct_https_get: резолв по DoH на
    IP-literal, соединение на IP с SNI — системный hosts не читается.
    """
    last_error = ""
    for url in HTTP_PROBE_URLS:
        started = time.perf_counter()
        try:
            from checkers.hostres import direct_https_get

            response = direct_https_get(
                url,
                timeout=timeout,
                max_bytes=4 * 1024,
                headers={"User-Agent": "SubGenerator/1.0"},
            )
            if response.ok and 200 <= response.status < 400:
                latency_ms = (time.perf_counter() - started) * 1000.0
                return True, latency_ms, url, ""
            last_error = f"{url}: unexpected status {response.status or '?'}"
        except Exception as exc:
            last_error = f"{url}: {type(exc).__name__}: {exc}"
    return False, None, None, last_error


def local_blocked_media_check(
    timeout: float = 4.0,
) -> tuple[dict[str, dict[str, object]], str]:
    """Проверка доступности заблокированных целей (chatgpt/instagram/tg).

    Методология Karing: HTTPS GET к блокированным в РФ целям — если запрос
    проходит, сеть корректно маршрутизирует к блокированным ресурсам.
    Используется только как информационный сигнал, не влияет на internet_ok.

    Используем GET вместо HEAD: chatgpt.com возвращает 403 на HEAD без
    Accept-Language/Cookie, но GET с User-Agent браузера работает.

    Возвращает (targets, last_error), где targets — host -> {
    "ok": bool, "latency_ms": float | None, "status": int}.
    """
    targets: dict[str, dict[str, object]] = {}
    last_error = ""

    for host, url in BLOCKED_MEDIA_HTTP_PROBES:
        started = time.perf_counter()
        try:
            # Мимо системного hosts: DoH-резолв на IP-literal + IP+SNI.
            from checkers.hostres import direct_https_get

            response = direct_https_get(
                url,
                timeout=timeout,
                max_bytes=16 * 1024,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                },
            )
            status = response.status if response.ok else 0
            # Считаем успехом любой ответ < 500. 403 от chatgpt без
            # cookies — это «сервер доступен, но требует авторизацию»,
            # что всё равно означает: соединение установлено.
            ok = 200 <= status < 500
            latency_ms = (time.perf_counter() - started) * 1000.0
            targets[host] = {
                "ok": ok,
                "latency_ms": round(latency_ms, 1) if ok else None,
                "status": int(status),
            }
            if not ok:
                last_error = f"{url}: status {status}"
        except Exception as exc:
            targets[host] = {"ok": False, "latency_ms": None, "status": 0}
            last_error = f"{url}: {type(exc).__name__}: {exc}"

    return targets, last_error


def run_network_diagnostic(
    *,
    dns_timeout: float = 2.0,
    doh_timeout: float = 4.0,
    http_timeout: float = 4.0,
    include_blocked_media: bool = False,
) -> NetworkDiagnosticResult:
    """Выполняет все локальные проверки и агрегирует результат.

    Параметры:
        dns_timeout — таймаут UDP DNS-запроса к одному серверу, сек.
        doh_timeout — таймаут DoH-запроса, сек.
        http_timeout — таймаут HTTPS-проверки generate_204 и блокированных
            целей, сек.
        include_blocked_media — дополнительно проверить chatgpt.com,
            instagram.com и api.telegram.org. По умолчанию False: эти
            проверки полезны в основном на странице «Диагностика» в GUI;
            в preflight конвейера они не нужны (засоряют лог).
    """
    result = NetworkDiagnosticResult()

    # 1) UDP DNS с явным отслеживанием fallback. UDP приоритетен: на
    # заблокированных сетях DoH/DoT режутся, а UDP DNS на 53-м порту
    # обычно отвечает.
    (
        result.udp_dns_ok,
        result.udp_dns_latency_ms,
        result.udp_dns_server,
        result.dns_fallback_used,
        result.dns_fallback_server,
        err,
    ) = local_udp_dns_check_with_fallback(timeout=dns_timeout)
    if err:
        result.errors.append(f"udp_dns: {err}")

    # 2) DoH (Cloudflare/Google/AdGuard/OpenDNS).
    result.doh_ok, result.doh_latency_ms, result.doh_endpoint, err = local_doh_check(
        timeout=doh_timeout
    )
    if err:
        result.errors.append(f"doh: {err}")

    # 3) Базовый HTTPS generate_204.
    result.http_ok, result.http_latency_ms, result.http_url, err = local_http_check(
        timeout=http_timeout
    )
    if err:
        result.errors.append(f"http: {err}")

    # 4) Заблокированные цели — факультативно (GUI-диагностика).
    if include_blocked_media:
        result.blocked_targets, err = local_blocked_media_check(
            timeout=http_timeout
        )
        if err:
            result.errors.append(f"blocked_media: {err}")

    return result


if __name__ == "__main__":
    diag = run_network_diagnostic(include_blocked_media=True)
    print(diag.as_dict())
