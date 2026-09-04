"""Реальная DPI-проверка узла.

Проверяет, способен ли узел (vless/vmess/trojan/ss/hy2) работать при
DPI-блокировках. В отличие от простого HEAD-запроса, использует методы
инструментария dpi-ch (dpich):

1. **alive** — реальный TLS-хендшейк и HTTP-ответ от целевого хоста;
2. **tcp 16-20 / l4-25** — передача большого случайного payload через
   прокси и проверка, что данные реально проходят (не блокируются DPI);
3. **siberian** — множественные TLS-хендшейки с разными SNI для выявления
   "сибирских" ограничений.

Узел считается прошедшим DPI-проверку, если alive и tcp 16-20 успешны
(данные реально передаются через прокси к заблокированному ресурсу).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import base
from .base import (
    TCP1620_DETECTED,
    TCP1620_NOT_DETECTED,
)

logger = logging.getLogger(__name__)


# Целевой хост по умолчанию для DPI-проверки.
# Instagram заблокирован в РФ (реальная DPI-проверка) и, в отличие от
# chatgpt.com (OpenAI), менее агрессивно блокирует IP-адреса дата-центров,
# из которых работают многие VPN-узлы. Это снижает ложные FAIL.
DPI_DEFAULT_TARGET = "instagram.com"

# Несколько заблокированных целей для DPI-проверки. Мобильные операторы
# применяют более агрессивный DPI (на телефоне dpi-ch показывает alive:
# unknown и tcp 16-20: detected, хотя на ПК всё чисто). Проверка по нескольким
# целям + больше попыток alive отбирает узлы, которые реально пробивают
# блокировки и в мобильной сети.
DPI_DEFAULT_TARGETS = (
    DPI_DEFAULT_TARGET,  # instagram.com
    "facebook.com",
    "x.com",
)
# Таймаут DPI-проверки (сек).
DPI_TIMEOUT = 10.0
# Сколько целей должно пройти, чтобы узел считался принятым (доля от общего).
DPI_ACCEPT_FRACTION = 0.5

# Дополнительный бюджет run_with_node при включённом Zapret-suite: POST 64KB
# на 8 целей x 3 протокола + HTTP-тест — это ещё ~95с худшего случая.
DPI_SUITE_BUDGET = 95.0

# Минимум «сетевых» проб (таймауты хендшейка + freeze), начиная с которого
# медленная сеть может «амнистировать» узла по suite (вместе с network_slow
# и пройденной классикой). Реальный кейс 2026-09-02: мобильная сеть днём —
# 1656 таймаутов хендшейка из 2328 проб, «dpi отбраковал ВСЕ конфиги», хотя
# ночью те же узлы проходили suite 23/24, а классика проходила и днём.
DPI_SUITE_SLOW_MIN_PROBES = 3





@dataclass
class DpiCheckResult:
    """Результат DPI-проверки узла (классика + Zapret-suite, если включён)."""

    accepted: bool
    alive: bool = False
    tcp1620: bool = False
    tcp1620_level: str = TCP1620_NOT_DETECTED
    siberian: bool = True
    cidr: bool = True
    reason: str = ""
    details: dict = field(default_factory=dict)
    # --- Zapret-suite (внутри DPI-этапа; заполняется при run_suite=True) ---
    suite_run: bool = False  # suite выполнялся на этом core-процессе
    suite_accepted: bool = False
    suite_score: float = 0.0
    suite_score_text: str = ""  # '55/60' как в логах Zapret
    suite_reason: str = ""
    suite_details: dict = field(default_factory=dict)

    def row(self) -> dict:
        return {
            "accepted": self.accepted,
            "alive": self.alive,
            "tcp1620": self.tcp1620,
            "tcp1620_level": self.tcp1620_level,
            "siberian": self.siberian,
            "cidr": self.cidr,
            "reason": self.reason,
            "details": self.details,
            "suite_run": self.suite_run,
            "suite_accepted": self.suite_accepted,
            "suite_score": round(self.suite_score, 3),
            "suite_score_text": self.suite_score_text,
            "suite_reason": self.suite_reason,
        }





# Ресурсы для CIDR-whitelist проверки (как в dpich cidrwhitelist.go).
_CIDR_REGULAR_HOSTS = ("github.com", "ru.wikipedia.org", "www.google.com")
_CIDR_WHITELISTED_HOSTS = ("ya.ru", "vk.ru")


def _alive_retry(
    host: str,
    port: int,
    target_host: str,
    timeout: float,
    attempts: int = 5,
) -> bool:
    """TLS-хендшейк с повторами.

    Alive — это чистый TLS-хендшейк (ClientHello -> Finished), без HTTP.
    Ботовая защита (Cloudflare challenge, Instagram cookie-блок) выдаётся уже
    поверх TLS, поэтому на сам handshake не влияет — это надёжный критерий.
    Единственная причина ложного FAIL — единичный сетевой сбой на нагруженном
    edge-сервере, поэтому делаем несколько попыток. На мобильном операторе
    DPI агрессивнее (dpi-ch на телефоне показывает alive: unknown) — больше
    попыток снижает ложные FAIL.
    """
    for _ in range(max(1, attempts)):
        if base.tls_handshake_ok(host, port, target_host, 443, target_host, timeout):
            return True
    return False


def _target_ok(
    host: str,
    port: int,
    target_host: str,
    timeout: float,
) -> tuple[bool, str, bool, str]:
    """Проверить одну заблокированную цель.

    Возвращает (alive, tcp1620_level, siberian, reason).
    Узел считается прошедшим цель, если alive + tcp 16-20 успешны.
    """
    alive = _alive_retry(host, port, target_host, timeout)
    if not alive:
        return False, TCP1620_DETECTED, False, "alive_failed"

    tcp1620_level = base.tcp1620_payload_ok(host, port, target_host, 443, target_host, timeout)
    if tcp1620_level == TCP1620_DETECTED:
        return True, tcp1620_level, False, "tcp1620_blocked"

    siberian = base.siberian_check_ok(host, port, target_host, 443, target_host, timeout)
    return True, tcp1620_level, siberian, ""


def _run_checks(
    host: str,
    port: int,
    target_host: str,
    timeout: float,
    require_siberian: bool = False,
    require_cidr: bool = False,
    target_hosts: tuple[str, ...] = (),
    run_suite: bool = False,
    suite_targets=None,
    suite_timeout: float = 5.0,
    suite_min_score: float = 0.75,
    suite_http_test: bool = True,
    rtt_hint_ms: float = 0.0,
) -> DpiCheckResult:
    """Выполнить набор DPI-проверок через локальный SOCKS5-прокси.

    Проверяет несколько заблокированных целей (``target_hosts``): для каждой —
    alive (TLS-хендшейк с повторами) + tcp 16-20 (передача большого payload).
    Узел принимается, если доля успешных целей >= ``DPI_ACCEPT_FRACTION``.

    Мобильные операторы применяют более агрессивный DPI (на телефоне dpi-ch
    показывает alive: unknown и tcp 16-20: detected, хотя на ПК всё чисто).
    Multi-target проверка + больше попыток alive отбирает узлы, которые реально
    пробивают блокировки и в мобильной сети.

    ``require_siberian`` / ``require_cidr`` — включают siberian/CIDR-whitelist
    как обязательные отсеивающие проверки. Без флагов они информативные.

    Zapret-suite (``run_suite=True``): POST 64KB на цели ``suite_targets`` по
    3 протоколам (HTTP/1.1, TLS1.2, TLS1.3) + HTTP-тест выполняется НА ТОМ ЖЕ
    core-процессе узла (один run_with_node — без дубля tcp 16-20). Итоговый
    вердикт: классика AND suite; причина падения suite — ``suite_*``.

    ``rtt_hint_ms`` — p50-латентность initial_check (мс), передаётся в сьют
    для адаптации параметров под сеть (см. ``zapret.effective_suite_params``):
    таймаут RTT×8 (до 20с), на медленных сетях 4 цели / без HTTP-теста /
    порог 0.5. Без хинта — прежнее поведение.
    """
    targets = tuple(target_hosts) or (target_host,)
    per_target: list[dict] = []
    ok_count = 0
    for t in targets:
        alive, tcp1620_level, siberian, reason = _target_ok(host, port, t, timeout)
        per_target.append(
            {
                "target": t,
                "alive": alive,
                "tcp1620_level": tcp1620_level,
                "siberian": siberian,
                "reason": reason,
            }
        )
        if alive and tcp1620_level != TCP1620_DETECTED:
            ok_count += 1

    # tcp 16-20: отсеиваем только при detected (write заблокирован — DPI реально
    # ограничивает передачу). possible/probably/unlikely не отсеивают, чтобы не
    # терять рабочие узлы из-за неопределённости.
    need = max(1, int(round(len(targets) * DPI_ACCEPT_FRACTION)))
    accepted = ok_count >= need
    reason = "ready" if accepted else f"targets_passed={ok_count}/{len(targets)} below={need}"

    # 3. siberian: множественные TLS-хендшейки к целевому хосту (обязательный, если включён).
    siberian_ok = all(p["siberian"] for p in per_target)
    if accepted and require_siberian and not siberian_ok:
        return DpiCheckResult(
            accepted=False,
            alive=True,
            tcp1620=True,
            tcp1620_level=per_target[0]["tcp1620_level"],
            siberian=False,
            reason="siberian_blocked",
            details={"targets": per_target},
        )

    # 4. CIDR-whitelist: доступность обычных (не whitelisted) ресурсов.
    #    Информативная проверка — не отсеивает узел (ложные срабатывания
    #    возможны из-за гео-блокировок), а фиксирует результат в details.
    #    С флагом require_cidr становится обязательной.
    regular_alive = sum(
        1
        for h in _CIDR_REGULAR_HOSTS
        if base.tls_handshake_ok(host, port, h, 443, h, timeout)
    )
    whitelisted_alive = sum(
        1
        for h in _CIDR_WHITELISTED_HOSTS
        if base.tls_handshake_ok(host, port, h, 443, h, timeout)
    )
    cidr_ok = regular_alive > 0
    if accepted and require_cidr and not cidr_ok:
        reason = "cidr_whitelist_detected" if whitelisted_alive > 0 else "no_internet_access"
        return DpiCheckResult(
            accepted=False,
            alive=True,
            tcp1620=True,
            tcp1620_level=per_target[0]["tcp1620_level"],
            siberian=siberian_ok,
            cidr=False,
            reason=reason,
            details={
                "targets": per_target,
                "cidr_regular_alive": regular_alive,
                "cidr_whitelisted_alive": whitelisted_alive,
            },
        )

    result = DpiCheckResult(
        accepted=accepted,
        alive=ok_count > 0,
        tcp1620=accepted,
        tcp1620_level=per_target[0]["tcp1620_level"],
        siberian=siberian_ok,
        cidr=cidr_ok,
        reason=reason,
        details={
            "targets": per_target,
            "cidr_regular_alive": regular_alive,
            "cidr_whitelisted_alive": whitelisted_alive,
        },
    )

    # --- Zapret-suite НА ТОМ ЖЕ core-процессе (слияние Task 16) ---
    # Suite имеет смысл только для узлов с пройденной классикой: вердикт —
    # «классика AND suite», узел с проваленной классикой отбракован в любом
    # случае, а ~90с suite-проб на него — впустую (и затирали честную причину
    # «targets_passed=...» на «suite_score=...»).
    if run_suite and suite_targets and result.accepted:
        from .zapret import _run_zapret_checks  # отложенный импорт (без цикла)

        try:
            zap = _run_zapret_checks(
                host,
                port,
                list(suite_targets),
                float(suite_timeout),
                bool(suite_http_test),
                float(suite_min_score),
                rtt_hint_ms=rtt_hint_ms,
            )
            result.suite_run = True
            result.suite_accepted = bool(zap.accepted)
            result.suite_score = float(zap.score)
            result.suite_score_text = zap.score_text
            result.suite_reason = zap.reason
            result.details = dict(result.details)
            result.details["suite"] = zap.row()
            # Вердикт: классика AND suite. Причина падения по suite —
            # suite_* (по ней конвейер/лог отличают, на чём именно упал узел).
            if not zap.accepted:
                # Медленная сеть доступа, а не узел (фикс «dpi уронил всё на
                # мобильной сети»): классика (alive + tcp 16-20 к instagram/
                # facebook/x) ПРОШЛА — узел реально пробивает блокировки, а
                # suite завален таймаутами хендшейка/freeze на медленном
                # канале. Suite не вето: узел принят, причина — маркер
                # suite_slow_network (счётчик в отчёте/логе). Настоящая
                # цензура на быстрой сети по-прежнему отсеивает (network_slow
                # там False).
                slow_network_probes = zap.timeout_probes + zap.blocked_probes
                if (
                    zap.network_slow
                    and slow_network_probes
                    >= max(DPI_SUITE_SLOW_MIN_PROBES, zap.total_probes // 2)
                ):
                    result.reason = "suite_slow_network"
                else:
                    result.accepted = False
                    result.reason = f"suite_{zap.reason}"
        except Exception as exc:
            # Suite — часть DPI-проверки: ошибка движка не должна ронять
            # классический вердикт, но фиксируется в результате.
            result.suite_run = True
            result.suite_accepted = False
            result.suite_reason = f"suite_error: {exc}"
            result.accepted = False
            result.reason = "suite_error"
            logger.warning("DPI suite failed on node: %s", exc)

    return result


def check_node_dpi_detailed(
    node_url: str,
    target_host: str = DPI_DEFAULT_TARGET,
    timeout: float = DPI_TIMEOUT,
    root_dir: Optional[Path] = None,
    require_siberian: bool = False,
    require_cidr: bool = False,
    target_hosts: tuple[str, ...] | None = None,
    run_suite: bool = False,
    suite_targets=None,
    suite_timeout: float = 5.0,
    suite_min_score: float = 0.75,
    suite_http_test: bool = True,
    rtt_hint_ms: float = 0.0,
) -> DpiCheckResult:
    """Детальная DPI-проверка узла (возвращает DpiCheckResult).

    По умолчанию проверяет несколько заблокированных целей
    (``DPI_DEFAULT_TARGETS``) — это отбирает узлы, которые пробивают DPI и в
    мобильных сетях. Если ``target_host`` явно передан (отличается от
    ``DPI_DEFAULT_TARGET``), проверяется только одна цель. Либо можно передать
    ``target_hosts`` напрямую.

    ``require_siberian`` / ``require_cidr`` — включают siberian/CIDR-whitelist
    как обязательные отсеивающие проверки (по умолчанию информативные).

    Zapret-suite (``run_suite=True`` с ``suite_targets`` от
    ``zapret.load_dpi_suite``): выполняется НА ТОМ ЖЕ core-процессе узла —
    один подъем ядра на классику + suite, без дубля tcp 16-20. Вердикт:
    классика AND suite; причина падения по suite — ``suite_*``.

    ``rtt_hint_ms`` — p50-латентность initial_check (мс) — передаётся в сьют
    (адаптация параметров под сеть, см. ``zapret.effective_suite_params``).
    """
    if not node_url:
        return DpiCheckResult(accepted=False, reason="empty_node")

    if target_hosts is None:
        if target_host and target_host != DPI_DEFAULT_TARGET:
            targets = (target_host,)
        else:
            targets = DPI_DEFAULT_TARGETS
    else:
        targets = tuple(target_hosts) or (target_host or DPI_DEFAULT_TARGET,)

    def _check(host: str, port: int) -> DpiCheckResult:
        return _run_checks(
            host,
            port,
            target_host or DPI_DEFAULT_TARGET,
            timeout,
            require_siberian,
            require_cidr,
            target_hosts=targets,
            run_suite=run_suite,
            suite_targets=suite_targets,
            suite_timeout=suite_timeout,
            suite_min_score=suite_min_score,
            suite_http_test=suite_http_test,
            rtt_hint_ms=rtt_hint_ms,
        )

    # Multi-target занимает больше времени — увеличиваем общий бюджет.
    # Zapret-suite на том же core-процессе добавляет ~95с худшего случая;
    # на медленной сети suite-таймаут адаптивно растёт (до 20с: rtt_hint
    # или baseline) — бюджет масштабируется вместе с ним, чтобы run_with_node
    # не убил ядро посреди проб (иначе узел ложно получает node_start_failed).
    budget = max(8.0, timeout * max(1, len(targets)) * 4.0)
    if run_suite:
        budget += DPI_SUITE_BUDGET * max(1.0, float(suite_timeout) / 5.0) + 5.0
    result = base.run_with_node(node_url, _check, timeout=timeout, root_dir=root_dir, budget=budget)
    if result is None:
        return DpiCheckResult(accepted=False, reason="node_start_failed")
    return result



if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m checkers.dpi <node_url> [target_host]")
        sys.exit(1)
    url = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else DPI_DEFAULT_TARGET
    res = check_node_dpi_detailed(url, target_host=target)
    print(f"DPI check for {url}: {'PASS' if res.accepted else 'FAIL'}")
    print(f"  alive={res.alive} tcp1620={res.tcp1620} siberian={res.siberian} reason={res.reason}")
