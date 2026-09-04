"""Предварительная локальная диагностика сети перед запуском проверок узлов.

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
4. Наличие/возможность TUN-адаптера — Windows netsh/ipconfig.
5. Доступность заблокированных в РФ медиа-целей: chatgpt.com,
   chat.openai.com, instagram.com — факультативно (include_blocked_media=True).
   Это не влияет на internet_ok, но позволяет зафиксировать, проходит ли
   TUN-маршрут к блокированным ресурсам.

Функции из checkers.resilience (udp_dns_check, dns_over_https_check) здесь
НЕ используются: они проверяют DNS ЧЕРЕЗ SOCKS-прокси поднятого узла, а нам
нужно проверить саму локальную сеть до запуска узлов.

Параметризация TUN:
    run_network_diagnostic(tun_iface="sgtun0") — если указано имя активного
    TUN-интерфейса, проверки выполняются с привязкой к этому интерфейсу
    (на Windows привязка по интерфейсу не поддерживается напрямую, поэтому
    мы полагаемся на auto_route ядра: системный трафик автоматически уходит
    в TUN). Это переиспользует NetworkDiagnosticResult, добавляя только
    контекст «через какой интерфейс шёл трафик».
"""
from __future__ import annotations

import contextlib
import socket
import subprocess
import time
import urllib.request
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
    # пробуем альтернативные провайдеры.
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

# Заблокированные в РФ медиа-цели. Проверка факультативна — она не влияет
# на internet_ok, но позволяет отличить «узел/TUN пропускает блокировки»
# от «узел работает, но блокировки на стороне провайдера».
BLOCKED_MEDIA_HTTP_PROBES = [
    # chatgpt.com — главное зеркало ChatGPT, часто блокируется по SNI/IP.
    ("chatgpt.com", "https://chatgpt.com/"),
    # chat.openai.com — legacy-домен, иногда блокируется отдельно.
    ("chat.openai.com", "https://chat.openai.com/"),
    # instagram.com — главный домен Instagram.
    ("instagram.com", "https://www.instagram.com/"),
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
    tun_present: bool = False
    tun_ready: bool = False
    tun_detail: str = ""
    # DNS-fallback: True, если первый сервер (1.1.1.1) НЕ ответил, но
    # один из резервных (9.9.9.9/AdGuard/OpenDNS) — ответил. Полезный
    # сигнал для диагностики: «основной DNS режется, но запасной работает».
    dns_fallback_used: bool = False
    dns_fallback_server: str | None = None
    # chatgpt/instagram — факультативные проверки (include_blocked_media).
    chatgpt_ok: bool = False
    chatgpt_latency_ms: float | None = None
    instagram_ok: bool = False
    instagram_latency_ms: float | None = None
    # Имя активного TUN-интерфейса, через который шли проверки (если
    # параметризовано). На Windows это информационное поле: реальную
    # маршрутизацию делает ядро (auto_route=True).
    tun_iface: str = ""
    errors: list[str] = field(default_factory=list)

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
            "tun_present": self.tun_present,
            "tun_ready": self.tun_ready,
            "tun_detail": self.tun_detail,
            "dns_fallback_used": self.dns_fallback_used,
            "dns_fallback_server": self.dns_fallback_server,
            "chatgpt_ok": self.chatgpt_ok,
            "chatgpt_latency_ms": self.chatgpt_latency_ms,
            "instagram_ok": self.instagram_ok,
            "instagram_latency_ms": self.instagram_latency_ms,
            "tun_iface": self.tun_iface,
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
    Cloudflare/Google, затем AdGuard/OpenDNS как fallback. Fallback на
    urlopen (hosts-зависимый) — только если hostres недоступен.
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
) -> tuple[bool, float | None, bool, float | None, str]:
    """Проверка доступности chatgpt.com и instagram.com.

    Методология Karing: HTTPS GET к блокированным в РФ целям — если запрос
    проходит, узел/TUN корректно маршрутизирует к блокированным ресурсам.
    Используется только как информационный сигнал, не влияет на internet_ok.

    Используем GET вместо HEAD: chatgpt.com возвращает 403 на HEAD без
    Accept-Language/Cookie, но GET с User-Agent браузера работает.

    Возвращает (chatgpt_ok, chatgpt_latency_ms, instagram_ok,
    instagram_latency_ms, last_error).
    """
    chatgpt_ok = False
    chatgpt_latency: float | None = None
    instagram_ok = False
    instagram_latency: float | None = None
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
            # Считаем успехом любой 2xx/3xx ответ. 403 от chatgpt без
            # cookies — это «сервер доступен, но требует авторизацию»,
            # что всё равно означает: соединение установлено.
            if 200 <= status < 500:
                latency_ms = (time.perf_counter() - started) * 1000.0
                if "chatgpt" in host or "openai" in host:
                    if not chatgpt_ok or (chatgpt_latency is not None and latency_ms < chatgpt_latency):
                        chatgpt_ok = True
                        chatgpt_latency = latency_ms
                elif "instagram" in host:
                    if not instagram_ok or (instagram_latency is not None and latency_ms < instagram_latency):
                        instagram_ok = True
                        instagram_latency = latency_ms
            else:
                last_error = f"{url}: status {status}"
        except Exception as exc:
            last_error = f"{url}: {type(exc).__name__}: {exc}"

    return chatgpt_ok, chatgpt_latency, instagram_ok, instagram_latency, last_error


def _windows_tun_detail(iface: str = "") -> tuple[bool, str]:
    """Проверка TUN-адаптера на Windows через netsh/ipconfig.

    Если указан iface (имя конкретного TUN-интерфейса), проверяем наличие
    именно этого адаптера. Иначе — ищем любой TUN/TAP/WireGuard-адаптер.
    """
    detail_parts: list[str] = []
    tun_present = False
    for cmd in (
        ["netsh", "interface", "show", "interface"],
        ["ipconfig", "/all"],
    ):
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5.0,
                encoding="utf-8",
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            low = output.lower()
            if iface and iface.lower() in low:
                tun_present = True
                detail_parts.append(f"iface:{iface}")
                break
            for marker in ("tun", "tap", "wireguard", "wg", "wintun", "utun"):
                if marker in low:
                    tun_present = True
                    detail_parts.append(marker)
                    break
        except Exception as exc:
            detail_parts.append(f"{cmd[0]}: {type(exc).__name__}: {exc}")
    return tun_present, "; ".join(detail_parts) or "no tun adapter found"


def local_tun_check(iface: str = "") -> tuple[bool, bool, str]:
    """Проверка TUN-адаптера. Возвращает (present, ready, detail).

    Если iface задан, проверяется именно этот интерфейс (используется
    при TUN-проверке узла: после поднятия ядра мы убеждаемся, что
    конкретный sgtun0 действительно появился в системе).
    """
    present, detail = _windows_tun_detail(iface)
    ready = present
    return present, ready, detail


def run_network_diagnostic(
    *,
    dns_timeout: float = 2.0,
    doh_timeout: float = 4.0,
    http_timeout: float = 4.0,
    include_blocked_media: bool = False,
    tun_iface: str = "",
) -> NetworkDiagnosticResult:
    """Выполняет все локальные проверки и агрегирует результат.

    Параметры:
        dns_timeout — таймаут UDP DNS-запроса к одному серверу, сек.
        doh_timeout — таймаут DoH-запроса, сек.
        http_timeout — таймаут HTTPS-проверки generate_204, сек.
        include_blocked_media — дополнительно проверить chatgpt.com и
            instagram.com. По умолчанию False: эти проверки полезны только
            когда трафик уже завёрнут в TUN/прокси (иначе они всегда
            упадут на заблокированной сети, засоряя лог).
        tun_iface — имя активного TUN-интерфейса. Используется для
            параметризации: если указано, проверяем именно этот интерфейс
            в local_tun_check (вместо поиска любого TUN).
    """
    result = NetworkDiagnosticResult()
    result.tun_iface = tun_iface

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

    # 4) TUN-адаптер (конкретный интерфейс или любой).
    result.tun_present, result.tun_ready, result.tun_detail = local_tun_check(iface=tun_iface)

    # 5) Заблокированные медиа — факультативно.
    if include_blocked_media:
        (
            result.chatgpt_ok,
            result.chatgpt_latency_ms,
            result.instagram_ok,
            result.instagram_latency_ms,
            err,
        ) = local_blocked_media_check(timeout=http_timeout)
        if err:
            result.errors.append(f"blocked_media: {err}")

    return result


if __name__ == "__main__":
    diag = run_network_diagnostic(include_blocked_media=True)
    print(diag.as_dict())
