#!/usr/bin/env python3
"""v18: поле «Вставка конфигов» понимает ссылки на подписки (happ://, https://)
и чистка интерфейса от пояснительных приписок.

Без Xvfb не проверяется GUI (запуск: xvfb-run -a python scripts/test_v18_import_links.py),
юнит-часть (_extract_sub_links, чистота исходников) работает без дисплея.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}  {detail}")


# ---------------------------------------------------------------- юнит-часть
from ui.pages.import_page import _extract_sub_links, _extract_configs  # noqa: E402

HAPP_LINK = "happ://crypt5/fzvdazV1R7mRpE1EuDJjWL70303SYm4Sw28vEUwG87Jam7etHiQGfPwZ3tpImr4RvgUsXNELRsPalCk2zoxdlqbw95nYmw7dgdt+Z0tr8fG/1D+Sol2CBfO+6ZDpy4z0H3mTKjllRyeZNsIwBSv6sKCdvXXpTnsPAdV/0/59RtIiSoqQqGXDl3jeWwGbAtVNaTm2PatEsgBSR8myGYSCAAASlU7h7upri2EgVCi4Kz55IPh+xnFSW/2O2S58wi7C8Eu4nXdoV5jOjuheJsUmRWJtYdMzE97aVckaN/5Z4TNgABifvZ1XDBxjPQN5xxBnxvysYPkPowWVZ4p5zr/nmCvcsYTU/FmtQ+UmlAsGV8UvSkaAcTGKFvFOcNlA4JuVeKtE+UgBdvh8Op2dlMgK5zPH/J3Eak2kJfkMJJuVzRRaOS9urSWQCBsSkzyPThId218hNJhFmmkuo79toTiA8rZrry8a9pJ0CRnWbBo4Mr9SGXWeaf9egMcKa8b4AChrqqmwVVOqpAQWYW/dHHXeSdweyTav9swSLo4ceOqfUC5FhKQnVK7bm242ydwolIJinTlrqoqPMikh2SZv/62nsX3hq64tMN/3D0WMPNXxpBtT5k6cUivlMer+ZuvHgn43RcpQQF0nKYcIGXHtrv9ixRT6Qo4elAVCEbIBUif1LPA74b56gENhon0Ue4f0k96yTxF6k8+aaTuB65mk/XztRDNNkxJbwYp1VQFTANgmfuKRy/+22WQXCW5iMy4yQu8/0orTYVl8IDfdaXSRm7D5OoUaEDNGVhz1CkVHzCz9EunhHn3Yj3LC0yTOzkjfyecmcpVx9Ze8dZ/8ypKzBe+Cgjbi4dp4FzL42qItgzcOsKBQRLVxkgEPf+K5tRgmDX+ouBniYCYFZdQy2vfMTHQyHyb691gYXgg09ybN0j9BFN+bbU70UXhjzmluxDjrtk38YzYIWgFuNsDdMum43IgKAlf8q/95BBNXXwD8hoArF+3w3hJVku7czahEfoM=ff"

check("happ-ссылка извлекается из вставки", _extract_sub_links(HAPP_LINK) == [HAPP_LINK])
check("https-ссылка извлекается", _extract_sub_links("https://sub.example.com/list.txt") == ["https://sub.example.com/list.txt"])
two = _extract_sub_links("https://a.example/1\nкакой-то текст\nhapp://crypt5/abc")
check("несколько ссылок в тексте", two == ["https://a.example/1", "happ://crypt5/abc"], str(two))
check("конфиги — не ссылки", _extract_sub_links("vless://uuid@1.2.3.4:443?x=1#n1\nтекст") == [])
check("пустой текст — пусто", _extract_sub_links("") == [])
check("ссылка с точкой в конце чистится", _extract_sub_links("см. https://sub.example/1.") == ["https://sub.example/1"])

# --------------------------------------------- чистота интерфейса от приписок
for rel in ("mysubs_page.py", "settings_page.py"):
    p = REPO / "python" / "ui" / "pages" / rel
    src = p.read_text(encoding="utf-8")
    check(f"{rel}: приписка «Вкладки: …» убрана", "Вкладки: " not in src)
    check(f"{rel}: пояснений «Раньше это были» нет", "Раньше это были" not in src and "Раньше Диагностика" not in src)
    check(f"{rel}: header в одной колонке (нет column=1 у шапки)", 'column=1, padx=(0, 20), pady=(20, 0), sticky="e"' not in src)

src_sp = (REPO / "python" / "ui" / "pages" / "sources_page.py").read_text(encoding="utf-8")
check("sources_page: тултип без «вкладка «Импорт»»", "(вкладка «Импорт»)" not in src_sp)

# ------------------------------------------------------------ GUI-часть (Xvfb)
have_display = bool(__import__("os").environ.get("DISPLAY"))
if have_display:
    import customtkinter as ctk  # noqa: E402

    ctk.set_appearance_mode("dark")
    app = ctk.CTk()
    app.geometry("900x700")
    app.withdraw()

    import ui.pages.import_page as ip  # noqa: E402
    import xray_runtime  # noqa: E402

    page = ip.ImportPage(app, app)

    # Синхронный «threading»: worker выполнится сразу, после() — тоже.
    class _FakeThread:
        def __init__(self, target=None, daemon=None):
            self._target = target

        def start(self):
            self._target()

    ip.threading.Thread = _FakeThread
    page.after = lambda delay, fn=None: fn() if callable(fn) else None

    # 1) happ-ссылка в поле вставки -> скачивание через _fetch_text -> конфиги
    calls = []

    def fake_fetch(url, timeout=20.0, log_sink=None):
        calls.append(url)
        return "vless://uuid@9.9.9.9:443?security=tls#saved1\nss://abc@1.2.3.4:8388#saved2"

    xray_runtime._fetch_text = fake_fetch
    saved_dir = Path(ip.paths.data_dir()) / "saved_subs"
    saved_dir.mkdir(parents=True, exist_ok=True)
    n_before = len(list(saved_dir.glob("url_*.txt")))

    page.txt_input.delete("1.0", "end")
    page.txt_input.insert("1.0", HAPP_LINK)
    page._save_paste()
    files = list(saved_dir.glob("url_*.txt"))
    check("вставка happ-ссылки: скачана через _fetch_text", calls == [HAPP_LINK], str(calls))
    check("вставка happ-ссылки: файл сохранён", len(files) == n_before + 1)
    if files:
        body = sorted(files, key=lambda f: f.stat().st_mtime)[-1].read_text(encoding="utf-8")
        check("вставка happ-ссылки: конфиги в файле", "vless://uuid@9.9.9.9" in body and "ss://abc@1.2.3.4" in body)
    status = page.lbl_paste_status.cget("text")
    check("вставка happ-ссылки: статус «Сохранено N»", status.startswith("Сохранено 2"), status)

    # 2) битая ссылка юзера -> внятная ошибка расшифровки, не «Конфиги не найдены»
    import runtime.fetch as rf  # noqa: E402
    xray_runtime._fetch_text = rf._fetch_text  # настоящий конвейер
    page.txt_input.delete("1.0", "end")
    page.txt_input.insert("1.0", HAPP_LINK)
    t0 = time.time()
    page._save_paste()  # синхронно (RSA-4096 ~0.3с)
    status = page.lbl_paste_status.cget("text")
    check("битая happ-ссылка: ошибка с причиной",
          status.startswith("Ошибка:") and ("нестандартный формат" in status or "RSA-блок" in status or "раскладка" in status),
          status[:140])
    check("битая happ-ссылка: не «Конфиги не найдены»", status != "Конфиги не найдены")
    check("битая happ-ссылка: быстро (<15с)", time.time() - t0 < 15)

    # 3) обычные конфиги — как раньше, без скачивания
    calls.clear()
    xray_runtime._fetch_text = fake_fetch
    page.txt_input.delete("1.0", "end")
    page.txt_input.insert("1.0", "vless://uuid@1.1.1.1:443?#manual")
    page._save_paste()
    check("конфигы в поле: без скачивания", calls == [])
    status = page.lbl_paste_status.cget("text")
    check("конфиги в поле: статус «Сохранено 1»", status.startswith("Сохранено 1"), status)

    # 4) мусор без ссылок -> «Конфиги не найдены»
    page.txt_input.delete("1.0", "end")
    page.txt_input.insert("1.0", "просто текст без всего")
    page._save_paste()
    check("мусор: «Конфиги не найдены»", page.lbl_paste_status.cget("text") == "Конфиги не найдены")

    # 5) URL-поле ходит через тот же конвейер
    calls.clear()
    page.entry_url.delete(0, "end")
    page.entry_url.insert(0, "https://sub.example.com/list.txt")
    page._import_from_url()
    check("URL-поле: качает через _fetch_text", calls == ["https://sub.example.com/list.txt"])

    # 6) приписок в живом дереве страницы нет (через настоящий SubGenApp)
    from ui.app import SubGenApp  # noqa: E402

    real_app = SubGenApp()
    real_app.update_idletasks()

    texts = []

    def walk(w, acc):
        try:
            for ch in w.winfo_children():
                t = getattr(ch, "cget", lambda k: None)("text")
                if isinstance(t, str) and t:
                    acc.append(t)
                walk(ch, acc)
        except Exception:
            pass

    walk(real_app.page_mysubs, texts)
    check("MySubsPage: приписки «Вкладки:» не отрисованы", not any(t.startswith("Вкладки:") for t in texts))
    check("MySubsPage: заголовок «Мои подписки» на месте", any(t == "Мои подписки" for t in texts))

    texts2 = []
    walk(real_app.page_settings_root, texts2)
    check("SettingsRootPage: приписки «Вкладки:» не отрисованы", not any(t.startswith("Вкладки:") for t in texts2))
    check("SettingsRootPage: заголовок «Настройки» на месте", any(t == "Настройки" for t in texts2))
    real_app.destroy()
    app.destroy()
else:
    print("[i] DISPLAY не задан — GUI-часть пропущена (запускайте под xvfb-run)")

print(f"\n=== v18 import links: {PASS} PASS, {FAIL} FAIL ===")
sys.exit(1 if FAIL else 0)
