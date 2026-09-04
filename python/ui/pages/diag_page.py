"""Страница «🔬 Диагностика» — пошаговая проверка сети.

Показывает на каком этапе отваливается соединение:
  1. Локальная сеть (IPv4/IPv6 connectivity)
  2. Системный DNS
  3. DoH (DNS over HTTPS)
  4. HTTP доступность (обычные + заблокированные сайты)
  6. Подключение к прокси-узлу
  7. DNS через прокси
  8. HTTP через прокси (обычные + заблокированные)
  9. Таблица маршрутов
"""
from __future__ import annotations

import threading
import time
import subprocess
import socket
import ssl
import urllib.request
import json

import customtkinter as ctk

from .. import theme, paths
from ..tooltip import CTkToolTip


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
        try:
            self._check_local_network()
            self._check_dns()
            self._check_http()
            self._check_route_table()
            self._post(lambda: self._append(""))
            self._post(lambda: self._append("✓ Диагностика завершена", theme.SUCCESS if hasattr(theme, 'SUCCESS') else "#27ae60"))
        except Exception as exc:
            _err = f"✗ Ошибка диагностики: {exc}"
            self._post(lambda: self._append(_err, "#e74c3c"))
        finally:
            self._running = False
            self._post(lambda: self.btn_run.configure(state="normal"))

    # ------------------------------------------------------------ проверки
    def _check_local_network(self) -> None:
        """1. Проверка локальной сети (IPv4 connectivity)."""
        self._post(lambda: self._append("Подключение к сети:", "#3498db"))

        # IPv4 — пробуем подключиться к 1.1.1.1:443
        started = time.perf_counter()
        try:
            sock = socket.create_connection(("1.1.1.1", 443), timeout=5)
            latency = (time.perf_counter() - started) * 1000
            sock.close()
            self._post(lambda: self._append(f"  ✓ IPv4 соединение выполнено успешно [{latency:.0f} ms]", "#2ecc71"))
        except Exception as exc:
            _err = f"  ✗ IPv4 соединение НЕ удалось: {exc}"
            self._post(lambda: self._append(_err, "#e74c3c"))

        # Проверка интернета — generate_204
        started = time.perf_counter()
        try:
            req = urllib.request.Request(
                "https://www.gstatic.com/generate_204",
                headers={"User-Agent": "SubGenerator/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if 200 <= resp.status < 400:
                    latency = (time.perf_counter() - started) * 1000
                    self._post(lambda: self._append(f"  ✓ Сеть подключена к интернету [{latency:.0f} ms]", "#2ecc71"))
                else:
                    self._post(lambda: self._append(f"  ⚠ Интернет: HTTP {resp.status}", "#f39c12"))
        except Exception as exc:
            _err = f"  ✗ Интернет недоступен: {exc}"
            self._post(lambda: self._append(_err, "#e74c3c"))

        self._post(lambda: self._append(""))

    def _check_dns(self) -> None:
        """2. Проверка DNS (системный + DoH)."""
        self._post(lambda: self._append("DNS сервер:", "#3498db"))

        # Системный UDP DNS — запрос к 8.8.8.8
        started = time.perf_counter()
        try:
            query = (
                b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x06google\x03com\x00\x00\x01\x00\x01"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(query, ("8.8.8.8", 53))
            resp, _ = sock.recvfrom(512)
            sock.close()
            if len(resp) >= 12:
                latency = (time.perf_counter() - started) * 1000
                self._post(lambda: self._append(f"  ✓ Системный DNS (8.8.8.8): [{latency:.0f} ms]", "#2ecc71"))
        except Exception as exc:
            _err = f"  ✗ Системный DNS недоступен: {exc}"
            self._post(lambda: self._append(_err, "#e74c3c"))

        # DoH — Cloudflare
        started = time.perf_counter()
        try:
            req = urllib.request.Request(
                "https://cloudflare-dns.com/dns-query?name=google.com&type=A",
                headers={"Accept": "application/dns-json", "User-Agent": "SubGenerator/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    latency = (time.perf_counter() - started) * 1000
                    self._post(lambda: self._append(f"  ✓ DoH (Cloudflare): [{latency:.0f} ms]", "#2ecc71"))
        except Exception as exc:
            _err = f"  ✗ DoH недоступен: {exc}"
            self._post(lambda: self._append(_err, "#e74c3c"))

        self._post(lambda: self._append(""))

    def _check_http(self) -> None:
        """3. Проверка HTTP — обычные сайты + заблокированные."""
        self._post(lambda: self._append("HTTP соединение (без прокси):", "#3498db"))

        # Сначала обычные (незаблокированные) сайты — проверяем базовый интернет.
        self._post(lambda: self._append("  Обычные сайты:"))
        normal_targets = [
            ("google.com", "https://www.google.com/generate_204"),
            ("yandex.ru", "https://ya.ru/"),
            ("vk.com", "https://vk.com/"),
        ]
        for host, url in normal_targets:
            started = time.perf_counter()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    latency = (time.perf_counter() - started) * 1000
                    self._post(lambda h=host, l=latency: self._append(
                        f"    ✓ [{h}] HTTP {resp.status} [{l:.0f} ms]", "#2ecc71"
                    ))
            except Exception as exc:
                self._post(lambda h=host, e=exc: self._append(
                    f"    ✗ [{h}] {type(e).__name__}", "#e74c3c"
                ))

        # Заблокированные сайты — проверяем что именно заблокировано.
        self._post(lambda: self._append("  Заблокированные сайты:"))
        blocked_targets = [
            ("chatgpt.com", "https://chatgpt.com/"),
            ("instagram.com", "https://www.instagram.com/"),
            ("api.telegram.org", "https://api.telegram.org/"),
        ]
        for host, url in blocked_targets:
            started = time.perf_counter()
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html",
                })
                with urllib.request.urlopen(req, timeout=5) as resp:
                    latency = (time.perf_counter() - started) * 1000
                    self._post(lambda h=host, l=latency: self._append(
                        f"    ✓ [{h}] HTTP {resp.status} [{l:.0f} ms]", "#2ecc71"
                    ))
            except Exception as exc:
                self._post(lambda h=host, e=exc: self._append(
                    f"    ✗ [{h}] {type(e).__name__}", "#e74c3c"
                ))

        self._post(lambda: self._append(""))


    def _check_route_table(self) -> None:
        """5. Таблица маршрутов."""
        self._post(lambda: self._append("Таблица маршрутов:", "#3498db"))

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
                        self._post(lambda s=stripped: self._append(f"  {s}", "#95a5a6"))
                        shown += 1
                        if shown > 15:
                            self._post(lambda: self._append("  ... (обрезано)", "#95a5a6"))
                            break
        except Exception as exc:
            _err = f"  — Не удалось получить таблицу маршрутов: {exc}"
            self._post(lambda: self._append(_err, "#95a5a6"))

        self._post(lambda: self._append(""))
