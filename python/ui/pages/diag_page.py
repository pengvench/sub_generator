"""Страница «🔬 Диагностика» — пошаговая проверка сети.

НЕ держит собственных inline-проверок (раньше дублировала
checkers/net_diagnostic.py): все проверки выполняет единая реализация
run_network_diagnostic(include_blocked_media=True), та же, что работает
в preflight конвейера. GUI только рендерит результат.

Шаги:
  1. Подключение к сети (generate_204)
  2. Системный DNS (UDP, с fallback-серверами)
  3. DoH (DNS over HTTPS)
  4. Заблокированные цели (chatgpt/instagram/api.telegram.org)
  5. СПИДТЕСТ: скорость сети по белым сервисам РФ (тот же каскад,
     что и в базовом замере конвейера: Яндекс.Интернетометр →
     tele2 → QMS-движок Билайна/speedtest.ru → OVH); download + upload
  6. Ошибки (если были)
  7. Таблица маршрутов (Windows route print — только для GUI)
"""
from __future__ import annotations

import subprocess
import threading

import customtkinter as ctk

from .. import theme
from checkers.net_diagnostic import run_network_diagnostic
from subgen.baseline import (
    BASELINE_CAP_MBITS,
    measure_download,
    measure_upload,
)

_OK = "#2ecc71"
_ERR = "#e74c3c"
_WARN = "#f39c12"
_HEAD = "#3498db"
_MUTED = "#95a5a6"


class DiagPage(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.configure(fg_color=theme.BG)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkLabel(
            self, text="🔬 Диагностика сети",
            font=ctk.CTkFont(size=22, weight="bold"), text_color=theme.TEXT,
        )
        header.grid(row=0, column=0, padx=20, pady=(16, 10), sticky="w")

        self.scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=theme.ACCENT,
            scrollbar_button_hover_color=theme.ACCENT_HOVER,
        )
        self.scroll.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")
        self.scroll.grid_columnconfigure(0, weight=1)

        # --- Кнопка запуска ---
        self.btn_run = ctk.CTkButton(
            self.scroll,
            text="▶ Запустить диагностику",
            height=40, corner_radius=8,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            text_color="#0C1014",
            command=self._on_run_clicked,
        )
        self.btn_run.grid(row=0, column=0, padx=12, pady=(8, 10), sticky="ew")

        # --- Текстовый вывод ---
        self.txt_output = ctk.CTkTextbox(
            self.scroll, height=500,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=theme.CARD, text_color=theme.TEXT,
            wrap="word",
        )
        self.txt_output.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="nsew")
        self.txt_output.configure(state="disabled")

        self._running = False

    # ------------------------------------------------------------ API
    def set_busy(self, busy: bool) -> None:
        self.btn_run.configure(state="disabled" if busy else "normal")

    # ------------------------------------------------------------ вывод
    def _append(self, text: str, color: str = "") -> None:
        """Добавить строку в текстовый вывод."""
        self.txt_output.configure(state="normal")
        if color:
            self.txt_output.tag_config(color, foreground=color)
            self.txt_output.insert("end", text + "\n", color)
        else:
            self.txt_output.insert("end", text + "\n")
        self.txt_output.see("end")
        self.txt_output.configure(state="disabled")

    def _clear(self) -> None:
        self.txt_output.configure(state="normal")
        self.txt_output.delete("1.0", "end")
        self.txt_output.configure(state="disabled")

    def _post(self, fn) -> None:
        try:
            self.after_idle(fn)
        except Exception:
            pass

    # ------------------------------------------------------------ запуск
    def _on_run_clicked(self) -> None:
        if self._running:
            return
        self._running = True
        self.btn_run.configure(state="disabled")
        self._clear()
        self._append("🔬 Диагностика сети")
        self._append("=" * 60)
        self._append("")

        threading.Thread(target=self._diag_worker, daemon=True, name="diag").start()

    def _diag_worker(self) -> None:
        """Фоновый прогон диагностики (та же реализация, что в конвейере)."""
        try:
            result = run_network_diagnostic(
                dns_timeout=2.0,
                doh_timeout=5.0,
                http_timeout=5.0,
                include_blocked_media=True,
            )

            # --- 1. Подключение к сети ---
            self._post(lambda: self._append("Подключение к сети:", _HEAD))
            if result.http_ok:
                latency = result.http_latency_ms or 0
                url = result.http_url or ""
                self._post(lambda: self._append(
                    f"  ✓ Сеть подключена к интернету [{latency:.0f} ms] ({url})", _OK))
            else:
                self._post(lambda: self._append("  ✗ Интернет недоступен (generate_204 не отвечает)", _ERR))
            self._post(lambda: self._append(""))

            # --- 2. Системный DNS ---
            self._post(lambda: self._append("DNS сервер:", _HEAD))
            if result.udp_dns_ok:
                latency = result.udp_dns_latency_ms or 0
                server = result.udp_dns_server or "?"
                extra = ""
                if result.dns_fallback_used:
                    extra = f" (fallback: основной DNS недоступен, ответил {result.dns_fallback_server})"
                self._post(lambda: self._append(
                    f"  ✓ Системный UDP DNS [{server}] [{latency:.0f} ms]{extra}", _OK))
            else:
                self._post(lambda: self._append("  ✗ Системный UDP DNS недоступен (все серверы, включая fallback)", _ERR))
            self._post(lambda: self._append(""))

            # --- 3. DoH ---
            self._post(lambda: self._append("DNS over HTTPS:", _HEAD))
            if result.doh_ok:
                latency = result.doh_latency_ms or 0
                endpoint = result.doh_endpoint or "?"
                self._post(lambda: self._append(
                    f"  ✓ DoH доступен [{endpoint}] [{latency:.0f} ms]", _OK))
            else:
                self._post(lambda: self._append("  ✗ DoH недоступен (Cloudflare/Google/AdGuard/OpenDNS)", _ERR))
            self._post(lambda: self._append(""))

            # --- 4. Заблокированные цели ---
            self._post(lambda: self._append("Заблокированные сайты (без прокси):", _HEAD))
            for host, info in result.blocked_targets.items():
                ok = bool(info.get("ok"))
                latency = info.get("latency_ms")
                if ok:
                    lat_text = f" [{latency:.0f} ms]" if isinstance(latency, (int, float)) else ""
                    self._post(lambda h=host, l=lat_text: self._append(
                        f"  ✓ [{h}] доступен{l}", _OK))
                else:
                    self._post(lambda h=host: self._append(f"  ✗ [{h}] недоступен", _ERR))
            self._post(lambda: self._append(""))

            # --- 5. Спидтест: скорость сети по белым сервисам ---
            self._run_speed_test()

            # --- 6. Ошибки (если были) ---
            if result.errors:
                self._post(lambda: self._append("Ошибки:", _WARN))
                for err in result.errors[:5]:
                    self._post(lambda e=err: self._append(f"  ⚠ {e}", _WARN))
                self._post(lambda: self._append(""))

            # --- 7. Таблица маршрутов (GUI-специфика) ---
            self._check_route_table()

            self._post(lambda: self._append(""))
            self._post(lambda: self._append("✓ Диагностика завершена", _OK))
        except Exception as exc:
            _err = f"✗ Ошибка диагностики: {exc}"
            self._post(lambda: self._append(_err, _ERR))
        finally:
            self._running = False
            self._post(lambda: self.btn_run.configure(state="normal"))

    # ------------------------------------------------------------ спидтест
    def _run_speed_test(self) -> None:
        """Спидтест-прогон по белым сервисам РФ (как в базовом замере).

        Тот же каскад, что и в конвейере (subgen/baseline.py): download
        Яндекс.Интернетометр → tele2 → QMS (движок «проверки скорости»
        Билайна/speedtest.ru) → OVH; upload — приёмник Яндекса → QMS.
        Если замер ≥ 100 Мбит — помечаем, что автопорог конвейера такой
        замер не слушает (быстрый проводной канал, VPN-конфиги столько
        не дают) — используется порог из UI.
        """
        self._post(lambda: self._append("Скорость сети (спидтест, белые сервисы РФ):", _HEAD))

        def _say(msg: str) -> None:
            # Строки прогресса каскада: «[baseline]     download: пробую yandex…»
            text = msg.replace("[baseline]", "").strip()
            if text:
                self._post(lambda t=text: self._append(f"  {t}", _MUTED))

        try:
            dl_kbps, dl_src = measure_download(timeout=10.0, log=_say)
        except Exception as exc:
            dl_kbps, dl_src = None, None
            self._post(lambda e=exc: self._append(f"  ⚠ ошибка замера download: {e}", _WARN))

        if dl_kbps:
            mbits = dl_kbps * 8 / 1000.0
            line = f"  ✓ Загрузка:  {dl_kbps:.0f} КБ/с (~{mbits:.1f} Мбит/с) via {dl_src}"
            if mbits >= BASELINE_CAP_MBITS:
                line += (
                    f"  [канал ≥ {BASELINE_CAP_MBITS:.0f} Мбит — автопорог замер "
                    "не слушает, используется порог из UI]"
                )
            self._post(lambda l=line: self._append(l, _OK))
        else:
            self._post(lambda: self._append(
                "  ✗ Загрузка не измерилась (белые сервисы недоступны)", _WARN))

        try:
            up_kbps, up_src = measure_upload(timeout=10.0, log=_say)
        except Exception as exc:
            up_kbps, up_src = None, None
            self._post(lambda e=exc: self._append(f"  ⚠ ошибка замера upload: {e}", _WARN))

        if up_kbps:
            up_mbits = up_kbps * 8 / 1000.0
            self._post(lambda: self._append(
                f"  ✓ Отдача:    {up_kbps:.0f} КБ/с (~{up_mbits:.1f} Мбит/с) via {up_src}", _OK))
        else:
            self._post(lambda: self._append(
                "  — Отдача не измерилась (приёмники выгрузки недоступны)", _WARN))

        self._post(lambda: self._append(""))

    # ------------------------------------------------------------ route table
    def _check_route_table(self) -> None:
        """Таблица маршрутов (только для GUI — отображение)."""
        self._post(lambda: self._append("Таблица маршрутов:", _HEAD))

        try:
            proc = subprocess.run(
                ["route", "print"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = (proc.stdout or "")
            lines = output.split("\n")
            in_ipv4 = False
            shown = 0
            for line in lines:
                if "IPv4" in line and "маршрутов" in line.lower():
                    in_ipv4 = True
                    continue
                if in_ipv4:
                    if "IPv6" in line or "Постоянные" in line or "Постоянн" in line:
                        if shown > 0:
                            break
                        continue
                    stripped = line.strip()
                    if stripped and not stripped.startswith("="):
                        self._post(lambda s=stripped: self._append(f"  {s}", _MUTED))
                        shown += 1
                        if shown > 15:
                            self._post(lambda: self._append("  ... (обрезано)", _MUTED))
                            break
        except Exception as exc:
            _err = f"  — Не удалось получить таблицу маршрутов: {exc}"
            self._post(lambda: self._append(_err, _MUTED))

        self._post(lambda: self._append(""))
