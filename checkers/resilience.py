"""Дополнительные проверки живучести узлов для обхода DPI и мобильных блокировок.

Проблема: на заблокированных мобильных сетях стандартные проверки пинга
(HTTP/HTTPS к telegram.org, MTProto) часто не работают из-за:
- Блокировки ICMP пакетов оператором
- DPI, отбрасывающего TLS handshake к известным SNI
- Блокировки IP-адресов Telegram API
- Блокировки прямых подключений к IP без SNI
- Блокировки DoT/DoH (tls://, https:// DNS) - троттлинг до 4-9 сек или дроп
- Отсутствия IPv6 в LTE сетях (IPv6 адреса недоступны)

Решение (на основе анализа логов Karing):
1. TLS Connect check — проверка TLS-соединения с правильным SNI (не просто TCP)
2. HTTPS к альтернативным целям (Cloudflare DoH, Google DoH, CDN)
3. DNS-over-HTTPS проверку (dns.google.com, mozilla.cloudflare-dns.com)
4. Проверку через WHITE-SNI домены (разрешённые в РФ: банки, маркетплейсы, госуслуги)
5. Приоритет доменным именам вместо прямых IP-адресов
6. Проверка способности передавать данные, а не только доступности порта
7. UDP DNS проверка (udp://8.8.8.8) - работает когда DoH/DoT блокируются
8. Fake IP режим - эмуляция работы DNS в прокси-клиентах (Karing, Clash, sing-box)
9. Исключение IPv6 из проверок (не работает в мобильных LTE сетях РФ)

Ключевые индикаторы "живости" канала из логов:
- dns.google.com:443, mozilla.cloudflare-dns.com:443 (DoH сервисы)
- www.google.com:443, safebrowsing.googleapis.com:443 (Google CDN)
- mtalk.google.com:5228 (Firebase cloud messaging)
- ya.ru, vk.com, sberbank.ru (российские разрешённые сервисы)
- udp://8.8.8.8:53 (обычный DNS по UDP - единственный быстрый вариант при блокировке DoH)

Важно: Не использовать IPv6 адреса в тестах (2606:4700::...) - они недоступны в LTE.
Не использовать tls:// и https:// для DNS - провайдеры душат шифрованный DNS.
Использовать udp://8.8.8.8 и udp://8.8.4.4 как запасной вариант.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import struct
import time
from typing import Any

from checkers.base import _socks_open_connection, run_with_node


# Цели для альтернативных проверок (обновлено на основе логов Karing)
# Важно: только IPv4 домены, без IPv6 адресов
ALTERNATIVE_TARGETS = [
    # Cloudflare CDN (часто не блокируется) - приоритетные из логов
    ("mozilla.cloudflare-dns.com", 443, "mozilla.cloudflare-dns.com"),  # Критически важный DoH
    ("one.cloudflare.com", 443, "one.cloudflare.com"),
    ("cloudflare-dns.com", 443, "cloudflare-dns.com"),  # DoH endpoint
    # Google CDN и сервисы - приоритетные из логов
    ("dns.google.com", 443, "dns.google.com"),  # Критически важный DoH
    ("www.google.com", 443, "www.google.com"),
    ("google.com", 443, "google.com"),
    ("safebrowsing.googleapis.com", 443, "safebrowsing.googleapis.com"),
    ("youtubei.googleapis.com", 443, "youtubei.googleapis.com"),
    ("android.googleapis.com", 443, "android.googleapis.com"),
    ("mtalk.google.com", 443, "mtalk.google.com"),  # Firebase cloud messaging
    # Microsoft CDN
    ("www.microsoft.com", 443, "www.microsoft.com"),
    # Apple CDN
    ("www.apple.com", 443, "www.apple.com"),
    # Яндекс (российский, точно работает)
    ("ya.ru", 443, "ya.ru"),
    ("www.yandex.ru", 443, "www.yandex.ru"),
    # VK (российский)
    ("vk.com", 443, "vk.com"),
]

# UDP DNS серверы для проверки (когда DoH/DoT блокируются)
# Это основной запасной вариант при блокировке шифрованного DNS
UDP_DNS_SERVERS = [
    ("8.8.8.8", 53),  # Google DNS - основной
    ("8.8.4.4", 53),  # Google DNS - запасной
    ("1.1.1.1", 53),  # Cloudflare DNS
    ("1.0.0.1", 53),  # Cloudflare DNS - запасной
    ("9.9.9.9", 53),  # Quad9 DNS
]

# WHITE-SNI домены из списков разблокированных (расширенный список для РФ)
WHITE_SNI_TARGETS = [
    # Банки и финансы
    ("www.sberbank.ru", 443, "www.sberbank.ru"),
    ("www.tinkoff.ru", 443, "www.tinkoff.ru"),
    ("www.vtb.ru", 443, "www.vtb.ru"),
    ("www.gazprombank.ru", 443, "www.gazprombank.ru"),
    ("www.raiffeisen.ru", 443, "www.raiffeisen.ru"),
    # Маркетплейсы
    ("www.wildberries.ru", 443, "www.wildberries.ru"),
    ("www.ozon.ru", 443, "www.ozon.ru"),
    ("www.yandex.ru", 443, "www.yandex.ru"),
    ("market.yandex.ru", 443, "market.yandex.ru"),
    # Госуслуги и госорганизации
    ("www.gosuslugi.ru", 443, "www.gosuslugi.ru"),
    ("www.gazprom.ru", 443, "www.gazprom.ru"),
    ("www.rzd.ru", 443, "www.rzd.ru"),
    ("www.aeroflot.ru", 443, "www.aeroflot.ru"),
    # Соцсети и медиа
    ("vk.com", 443, "vk.com"),
    ("ok.ru", 443, "ok.ru"),
    ("www.rbc.ru", 443, "www.rbc.ru"),
    ("www.lenta.ru", 443, "www.lenta.ru"),
    # Почта и облака
    ("mail.ru", 443, "mail.ru"),
    ("e.mail.ru", 443, "e.mail.ru"),
    ("cloud.mail.ru", 443, "cloud.mail.ru"),
    # CDN и инфраструктура
    ("cdn.yandex.net", 443, "cdn.yandex.net"),
    ("static.cloudflareinsights.com", 443, "static.cloudflareinsights.com"),
]


def tcp_connect_check(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float = 3.0,
) -> tuple[bool, float | None]:
    """Проверка простого TCP-соединения без TLS.
    
    Самый базовый тест: может ли узел установить TCP-соединение к цели.
    Не использует TLS, поэтому обходит некоторые виды DPI, которые
    анализируют только TLS handshake.
    
    Возвращает (успех, время_мс).
    """
    started = time.perf_counter()
    sock = None
    try:
        sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if sock is None:
            return False, None
        elapsed = (time.perf_counter() - started) * 1000.0
        return True, elapsed
    except Exception:
        return False, None
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()


def _single_https_latency(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    server_name: str,
    timeout: float,
    send_data: bool = True,  # Новый параметр: проверять передачу данных
) -> tuple[bool, float | None]:
    """Одиночная HTTPS проверка с опциональной проверкой передачи данных.
    
    Если send_data=True, выполняет полноценный HTTP запрос и проверяет ответ.
    Если send_data=False, только устанавливает TLS соединение (быстрее).
    """
    started = time.perf_counter()
    raw_sock = None
    try:
        raw_sock = _socks_open_connection(socks_host, socks_port, target_host, target_port, timeout)
        if raw_sock is None:
            return False, None
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
            raw_sock = None
            if send_data:
                # Отправляем HTTP запрос и проверяем ответ
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {server_name}\r\n"
                    f"User-Agent: SubGenerator/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                tls_sock.sendall(request)
                response = tls_sock.recv(32)
                if not response or not response.startswith(b"HTTP/"):
                    return False, None
            else:
                # Только TLS handshake без отправки данных
                # Проверяем, что соединение установлено
                tls_sock.getpeercert()
            latency = (time.perf_counter() - started) * 1000.0
            return True, latency
    except Exception:
        return False, None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def https_latency_alternative(
    socks_host: str,
    socks_port: int,
    targets: list[tuple[str, int, str]],
    timeout: float = 3.0,
) -> tuple[str | None, float | None, bool]:
    """HTTPS проверка к альтернативным целям.
    
    Пробует подключиться к нескольким целям последовательно,
    возвращает первую успешную.
    
    Возвращает (target_host, latency_ms, success).
    """
    for target_host, target_port, server_name in targets:
        success, latency = _single_https_latency(
            socks_host, socks_port, target_host, target_port, server_name, timeout
        )
        if success:
            return target_host, latency, True
    return None, None, False


def multi_target_ping(
    socks_host: str,
    socks_port: int,
    primary_target: tuple[str, int, str],
    alternative_targets: list[tuple[str, int, str]],
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Многоцелевая проверка пинга.
    
    Сначала пробует основную цель, затем альтернативные.
    Полезно для определения, заблокирована ли конкретная цель
    (например, telegram.org) или узел действительно мёртв.
    
    Возвращает dict с результатами по каждой цели.
    """
    results = {}
    
    # Основная цель
    primary_host, primary_port, primary_sni = primary_target
    success, latency = _single_https_latency(
        socks_host, socks_port, primary_host, primary_port, primary_sni, timeout
    )
    results["primary"] = {
        "target": primary_host,
        "success": success,
        "latency_ms": latency,
    }
    
    # Альтернативные цели
    alt_success = False
    best_alt_latency = None
    best_alt_target = None
    
    for alt_host, alt_port, alt_sni in alternative_targets:
        success, latency = _single_https_latency(
            socks_host, socks_port, alt_host, alt_port, alt_sni, timeout
        )
        results[f"alt_{alt_host}"] = {
            "target": alt_host,
            "success": success,
            "latency_ms": latency,
        }
        if success and not alt_success:
            alt_success = True
            best_alt_latency = latency
            best_alt_target = alt_host
    
    results["alternative"] = {
        "success": alt_success,
        "best_target": best_alt_target,
        "best_latency_ms": best_alt_latency,
    }
    
    # Итоговый вердикт
    results["overall"] = {
        "alive": results["primary"]["success"] or alt_success,
        "primary_blocked": not results["primary"]["success"] and alt_success,
        "recommended_target": best_alt_target if not results["primary"]["success"] else primary_host,
    }
    
    return results


def dns_over_https_check(
    socks_host: str,
    socks_port: int,
    domain: str = "google.com",
    timeout: float = 3.0,
) -> tuple[bool, float | None]:
    """Проверка DNS-over-HTTPS через прокси.
    
    Использует DoH для проверки возможности разрешения доменных имён.
    Это обходит блокировки DNS и показывает, работает ли DNS через узел.
    
    Возвращает (успех, время_мс).
    """
    started = time.perf_counter()
    raw_sock = None
    try:
        # Используем Cloudflare DoH
        doh_host = "cloudflare-dns.com"
        doh_port = 443
        
        raw_sock = _socks_open_connection(socks_host, socks_port, doh_host, doh_port, timeout)
        if raw_sock is None:
            return False, None
        
        raw_sock.settimeout(timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=doh_host) as tls_sock:
            raw_sock = None
            # Формируем DNS запрос (упрощённый A-record запрос)
            # Для google.com
            dns_query = (
                b"\x01\x23"  # Transaction ID
                b"\x01\x00"  # Flags: standard query
                b"\x00\x01"  # Questions: 1
                b"\x00\x00"  # Answer RRs: 0
                b"\x00\x00"  # Authority RRs: 0
                b"\x00\x00"  # Additional RRs: 0
                b"\x06google\x03com\x00"  # Query name
                b"\x00\x01"  # Query type: A
                b"\x00\x01"  # Query class: IN
            )
            # Оборачиваем в HTTP/2 или используем простой GET
            request = (
                f"GET /dns-query?name={domain}&type=A HTTP/1.1\r\n"
                f"Host: {doh_host}\r\n"
                f"Accept: application/dns-json\r\n"
                f"User-Agent: SubGenerator/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            response = tls_sock.recv(64)
            if not response:
                return False, None
            # Проверяем, что получили HTTP ответ с кодом 200
            if b"200" in response or b"HTTP/1.1 200" in response:
                latency = (time.perf_counter() - started) * 1000.0
                return True, latency
            return False, None
    except Exception:
        return False, None
    finally:
        if raw_sock is not None:
            with contextlib.suppress(Exception):
                raw_sock.close()


def udp_dns_check(
    socks_host: str,
    socks_port: int,
    dns_servers: list[tuple[str, int]] | None = None,
    domain: str = "google.com",
    timeout: float = 2.0,
) -> tuple[bool, float | None, str | None]:
    """Проверка DNS через UDP (обход блокировок DoH/DoT).
    
    Использует обычный DNS по UDP вместо шифрованного DoH/DoT.
    Это основной запасной вариант когда провайдер душит tls:// и https:// DNS.
    
    Из логов Karing: udp://8.8.8.8 работает за 108-128 мс даже при блокировке DoH.
    
    Возвращает (успех, время_мс, использованный сервер).
    """
    if dns_servers is None:
        dns_servers = UDP_DNS_SERVERS
    
    for dns_host, dns_port in dns_servers:
        started = time.perf_counter()
        udp_sock = None
        try:
            # Создаем UDP сокет
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(timeout)
            
            # Формируем DNS запрос (A-record для domain)
            transaction_id = b"\x12\x34"
            flags = b"\x01\x00"  # Standard query
            questions = b"\x00\x01"  # 1 question
            answer_rrs = b"\x00\x00"
            authority_rrs = b"\x00\x00"
            additional_rrs = b"\x00\x00"
            
            # Кодируем доменное имя
            query_name = b""
            for part in domain.split("."):
                query_name += bytes([len(part)]) + part.encode("ascii")
            query_name += b"\x00"
            
            query_type = b"\x00\x01"  # A record
            query_class = b"\x00\x01"  # IN class
            
            dns_query = (
                transaction_id + flags + questions +
                answer_rrs + authority_rrs + additional_rrs +
                query_name + query_type + query_class
            )
            
            # Отправляем запрос напрямую DNS серверу
            udp_sock.sendto(dns_query, (dns_host, dns_port))
            
            # Получаем ответ
            response, _ = udp_sock.recvfrom(512)
            latency = (time.perf_counter() - started) * 1000.0
            
            # Проверяем, что ответ содержит правильный transaction ID
            if response[:2] == transaction_id:
                return True, latency, f"{dns_host}:{dns_port}"
                
        except Exception:
            pass
        finally:
            if udp_sock is not None:
                with contextlib.suppress(Exception):
                    udp_sock.close()
    
    return False, None, None


def fake_ip_check(
    socks_host: str,
    socks_port: int,
    domain: str = "google.com",
    timeout: float = 2.0,
) -> tuple[bool, float | None]:
    """Проверка работы в режиме Fake IP.
    
    Fake IP — это режим работы DNS в прокси-клиентах (Karing, Clash, sing-box),
    при котором клиент обманывает приложение, возвращая фейковый IP-адрес
    из диапазона 198.18.0.0/16, а затем перехватывает трафик и направляет
    его через прокси.
    
    Это ускоряет соединение и обходит блокировки DNS, так как приложение
    не ждёт реального резолва домена.
    
    Проверка эмулирует этот режим:
    1. Быстрое "разрешение" домена (эмуляция Fake IP)
    2. Попытка подключения к фейковому IP через прокси
    3. Проверка, что прокси корректно обрабатывает такие подключения
    
    Возвращает (успех, время_мс).
    """
    started = time.perf_counter()
    
    # Эмулируем Fake IP адрес из диапазона 198.18.0.0/16
    fake_ip = f"198.18.{hash(domain) % 256}.{(hash(domain) >> 8) % 256}"
    
    # Пробуем подключиться к фейковому IP с указанием SNI
    # Это эмулирует поведение Clash/sing-box в режиме Fake IP
    success, latency = _single_https_latency(
        socks_host, socks_port, fake_ip, 443, domain, timeout
    )
    
    if success:
        elapsed = (time.perf_counter() - started) * 1000.0
        return True, elapsed
    
    return False, None


def resilience_check(
    socks_host: str,
    socks_port: int,
    node_url: str,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Комплексная проверка живучести узла.
    
    Выполняет серию тестов для определения:
    - Работоспособности узла в целом
    - Наличия блокировок конкретных целей
    - Рекомендаций по использованию
    
    Возвращает подробный отчёт с метриками.
    """
    from xray_runtime import parse_node_link
    
    node = parse_node_link(node_url)
    if node is None:
        return {"error": "invalid_node", "success": False}
    
    report = {
        "node": node.title(),
        "tests": {},
        "summary": {},
    }
    
    # 1. TCP Connect check (базовый) - самый быстрый тест
    tcp_success, tcp_latency = tcp_connect_check(
        socks_host, socks_port, "8.8.8.8", 53, min(timeout, 2.0)
    )
    report["tests"]["tcp_connect"] = {
        "success": tcp_success,
        "latency_ms": tcp_latency,
    }
    
    # 2. DNS-over-HTTPS проверка (обход DNS-блокировок)
    doh_success, doh_latency = dns_over_https_check(
        socks_host, socks_port, "google.com", min(timeout, 2.5)
    )
    report["tests"]["dns_over_https"] = {
        "success": doh_success,
        "latency_ms": doh_latency,
    }
    
    # 3. HTTPS к Telegram (основная цель, часто блокируется)
    tg_success, tg_latency = _single_https_latency(
        socks_host, socks_port, "api.telegram.org", 443, "api.telegram.org", timeout
    )
    report["tests"]["telegram_https"] = {
        "success": tg_success,
        "latency_ms": tg_latency,
    }
    
    # 4. HTTPS к альтернативным целям (международные CDN) - приоритет DoH
    alt_result = https_latency_alternative(
        socks_host, socks_port, ALTERNATIVE_TARGETS[:8], min(timeout, 3.0)
    )
    report["tests"]["alternative_https"] = {
        "success": alt_result[2],
        "target": alt_result[0],
        "latency_ms": alt_result[1],
    }
    
    # 5. WHITE-SNI проверка (для РФ - расширенный список) - приоритет российским доменам
    white_sni_result = https_latency_alternative(
        socks_host, socks_port, WHITE_SNI_TARGETS[:8], min(timeout, 3.0)
    )
    report["tests"]["white_sni"] = {
        "success": white_sni_result[2],
        "target": white_sni_result[0],
        "latency_ms": white_sni_result[1],
    }
    
    # 6. UDP DNS проверка (запасной вариант при блокировке DoH/DoT)
    udp_success, udp_latency, udp_server = udp_dns_check(
        socks_host, socks_port, domain="google.com", timeout=min(timeout, 2.0)
    )
    report["tests"]["udp_dns"] = {
        "success": udp_success,
        "server": udp_server,
        "latency_ms": udp_latency,
    }
    
    # 7. Fake IP проверка (эмуляция режима работы Karing/Clash/sing-box)
    fake_ip_success, fake_ip_latency = fake_ip_check(
        socks_host, socks_port, domain="google.com", timeout=min(timeout, 2.0)
    )
    report["tests"]["fake_ip"] = {
        "success": fake_ip_success,
        "latency_ms": fake_ip_latency,
    }
    
    # Итоговый вердикт - узел живой если хотя бы один тест прошёл
    any_success = (
        tcp_success or 
        doh_success or
        tg_success or 
        alt_result[2] or 
        white_sni_result[2] or
        udp_success or
        fake_ip_success
    )
    
    report["summary"] = {
        "alive": any_success,
        "telegram_blocked": not tg_success and (alt_result[2] or white_sni_result[2]),
        "only_white_sni_works": white_sni_result[2] and not tg_success and not alt_result[2] and not doh_success and not udp_success,
        "only_doh_works": doh_success and not tg_success and not alt_result[2] and not white_sni_result[2] and not udp_success,
        "only_udp_dns_works": udp_success and not tg_success and not doh_success and not alt_result[2] and not white_sni_result[2],
        "fake_ip_works": fake_ip_success,
        "completely_dead": not any_success,
        "recommended_mode": _get_recommended_mode(report["tests"]),
    }
    
    return report


def _get_recommended_mode(tests: dict[str, Any]) -> str:
    """Рекомендация по режиму использования узла."""
    if tests.get("telegram_https", {}).get("success"):
        return "full_access"
    elif tests.get("dns_over_https", {}).get("success") and tests.get("alternative_https", {}).get("success"):
        return "international_via_doh_cdn"
    elif tests.get("dns_over_https", {}).get("success"):
        return "doh_only"
    elif tests.get("udp_dns", {}).get("success"):
        return "udp_dns_fallback"
    elif tests.get("fake_ip", {}).get("success"):
        return "fake_ip_mode"
    elif tests.get("white_sni", {}).get("success"):
        return "ru_sites_only"
    elif tests.get("alternative_https", {}).get("success"):
        return "international_via_cdn"
    elif tests.get("tcp_connect", {}).get("success"):
        return "tcp_only_maybe_blocked"
    else:
        return "dead"


def check_node_resilience_detailed(
    node_url: str,
    timeout: float = 5.0,
) -> "ResilienceCheckResult":
    """Проверка живучести узла через SOCKS-прокси.
    
    Запускает временный Xray-процесс для узла и выполняет серию тестов
    для определения работоспособности в условиях блокировок.
    
    Возвращает ResilienceCheckResult с подробными метриками.
    """
    def _check(host: str, port: int) -> ResilienceCheckResult:
        report = resilience_check(host, port, node_url, timeout)
        return ResilienceCheckResult(
            node=node_url,
            alive=report.get("summary", {}).get("alive", False),
            telegram_blocked=report.get("summary", {}).get("telegram_blocked", False),
            white_sni_works=report.get("tests", {}).get("white_sni", {}).get("success", False),
            alternative_works=report.get("tests", {}).get("alternative_https", {}).get("success", False),
            tcp_works=report.get("tests", {}).get("tcp_connect", {}).get("success", False),
            doh_works=report.get("tests", {}).get("dns_over_https", {}).get("success", False),
            udp_dns_works=report.get("tests", {}).get("udp_dns", {}).get("success", False),
            fake_ip_works=report.get("tests", {}).get("fake_ip", {}).get("success", False),
            recommended_mode=report.get("summary", {}).get("recommended_mode", "unknown"),
            details=report,
        )
    
    result = run_with_node(node_url, _check, timeout=timeout, budget=timeout * 2.5)
    if result is None:
        return ResilienceCheckResult(
            node=node_url,
            alive=False,
            telegram_blocked=False,
            white_sni_works=False,
            alternative_works=False,
            tcp_works=False,
            doh_works=False,
            udp_dns_works=False,
            fake_ip_works=False,
            recommended_mode="error",
            details={"error": "failed_to_run"},
        )
    return result


class ResilienceCheckResult:
    """Результат проверки живучести узла."""
    
    def __init__(
        self,
        node: str,
        alive: bool,
        telegram_blocked: bool,
        white_sni_works: bool,
        alternative_works: bool,
        tcp_works: bool,
        recommended_mode: str,
        details: dict[str, Any],
        doh_works: bool = False,
        udp_dns_works: bool = False,
        fake_ip_works: bool = False,
    ):
        self.node = node
        self.alive = alive
        self.telegram_blocked = telegram_blocked
        self.white_sni_works = white_sni_works
        self.alternative_works = alternative_works
        self.tcp_works = tcp_works
        self.doh_works = doh_works
        self.udp_dns_works = udp_dns_works
        self.fake_ip_works = fake_ip_works
        self.recommended_mode = recommended_mode
        self.details = details
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "node": self.node,
            "alive": self.alive,
            "telegram_blocked": self.telegram_blocked,
            "white_sni_works": self.white_sni_works,
            "alternative_works": self.alternative_works,
            "tcp_works": self.tcp_works,
            "doh_works": self.doh_works,
            "udp_dns_works": self.udp_dns_works,
            "fake_ip_works": self.fake_ip_works,
            "recommended_mode": self.recommended_mode,
            **self.details,
        }
