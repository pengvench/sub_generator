#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты happ://cryptN/ расшифровки: crypt5 (legacy+salted), блочный RSA
crypt..crypt4, гибкий base64, переопределение ключей пользователем,
интеграция с _fetch_text (фейковый urlopen), поведение на битой ссылке.

Герметично: сети нет, urlopen подменён; ключи — реальные встроенные
(36 crypt5 + 4 pkcs1) + сгенерированные для раунд-трипов.
"""
import base64
import os
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, "/home/z/my-project/sub_generator/python")

import runtime.happ_decrypt as hd
from runtime.happ_decrypt import decrypt_happ_link, is_happ_link

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def rand_str(n: int, alphabet: str) -> str:
    return "".join(random.choice(alphabet) for _ in range(n))


ALNUM = string.ascii_letters + string.digits
URL = "https://freevpnhappcluchi.duckdns.org/sub/lew1ik2xiuohs9v3"


# ------------------------------------------------------------------ шифратор

def encrypt_crypt5(url: str, *, salted: bool, key_marker: str | None = None,
                   nonce: bytes | None = None, tag: bytes | None = None,
                   separator: bytes = b":") -> str:
    """Шифрование по образцу клиента Happ / hpwnr encrypt_crypt5."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    keys = hd._crypt5_keys()
    marker = key_marker or random.choice(list(keys))
    key = keys[marker]
    chacha_key = os.urandom(32)
    salt = rand_str(8, ALNUM).encode() if salted else None
    rsa_value = chacha_key if salt is None else bytes(chacha_key[i] ^ salt[i % 8] for i in range(32))
    swapped = hd._swap_pairs(b64e(rsa_value).encode())
    rsa_ct = key.public_key().encrypt(bytes(swapped), padding.PKCS1v15())
    nonce = nonce if nonce is not None else rand_str(12, ALNUM).encode()
    pt_b64 = hd._swap_pairs(b64e(url.encode()).encode())
    ct = ChaCha20Poly1305(chacha_key).encrypt(nonce, bytes(pt_b64), None)
    url_b64 = b64e(ct)
    body = bytearray(nonce)
    if salt is not None:
        body += (tag if tag is not None else rand_str(2, string.ascii_letters).encode())
        body += salt
    body += str(len(url_b64)).encode() + separator + url_b64.encode() + b64e(rsa_ct).encode()
    pre = marker[:4].encode() + bytes(body) + marker[4:8].encode()
    return "happ://crypt5/" + hd._block_pair_swap(pre).decode()


def encrypt_crypt(ordinal: int, url: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding
    key = hd._pkcs1_keys()[ordinal]
    ks = key.key_size // 8
    data, out = url.encode(), b""
    for off in range(0, len(data), ks - 11):
        out += key.public_key().encrypt(data[off:off + ks - 11], padding.PKCS1v15())
    return f"happ://crypt{'2345' * 0}{['', '2', '3', '4'][ordinal]}/" + b64e(out)


# ------------------------------------------------------------------- crypt5

print("== crypt5 ==")
for salted in (True, False):
    results = [decrypt_happ_link(encrypt_crypt5(URL, salted=salted)) == URL for _ in range(3)]
    check(f"раунд-трип {'salted' if salted else 'legacy'} ×3", all(results))
check("раунд-трип маркер vdfzfoff (ключ юзера)",
      decrypt_happ_link(encrypt_crypt5(URL, salted=True, key_marker="vdfzfoff")) == URL)

markers = random.sample(list(hd._crypt5_keys()), 5)
check("раунд-трип по 5 случайным маркерам из 36",
      all(decrypt_happ_link(encrypt_crypt5(URL, salted=i % 2 == 0, key_marker=m)) == URL
          for i, m in enumerate(markers)))

# salted с тегом, начинающимся с цифры: раскладка определяется по body[12],
# но код пробует ОБЕ раскладки — должно расшифроваться и так.
link = encrypt_crypt5(URL, salted=True, tag=b"7a")
check("salted с цифрой в теге (fallback-раскладка)", decrypt_happ_link(link) == URL)

# Разделитель — любой символ, не только ':' (Happ-совместимость).
link = encrypt_crypt5(URL, salted=False, separator=b"X")
check("разделитель != ':' (пропуск 1 символа)", decrypt_happ_link(link) == URL)

# Длинный URL (много блоков ChaCha-тела).
long_url = "https://example.com/sub/?token=" + "z" * 400
check("длинный URL (465 симв.)", decrypt_happ_link(encrypt_crypt5(long_url, salted=True)) == long_url)

# Пустой/мусорный payload.
errs: list[str] = []
check("payload из мусора -> None", decrypt_happ_link("happ://crypt5/abc", errors=errs) is None)
check("причина по мусору в errors", len(errs) > 0)

# ------------------------------------------------------------------- crypt..4

print("== crypt..crypt4 ==")
long_plain = "https://example.com/sub/" + "x" * 200
check("crypt (1024-бит, 2 блока, длинный URL)",
      decrypt_happ_link(encrypt_crypt(0, long_plain)) == long_plain)
check("crypt2 (4096-бит)", decrypt_happ_link(encrypt_crypt(1, URL)) == URL)
check("crypt3 (4096-бит)", decrypt_happ_link(encrypt_crypt(2, URL)) == URL)
check("crypt4 (4096-бит)", decrypt_happ_link(encrypt_crypt(3, URL)) == URL)

# Гибкий base64: url-safe алфавит без padding (в payload, схема не затрагивается).
link = encrypt_crypt(1, URL)
head, _, payload = link.partition("happ://crypt2/")
urlsafe = "happ://crypt2/" + payload.replace("+", "-").replace("/", "_").rstrip("=")
check("url-safe алфавит без padding", decrypt_happ_link(urlsafe) == URL)

# Потерянные ВЕДУЩИЕ символы b64 (= ведущие нулевые биты целого) — старое
# поведение zero-left-pad должно спасти ссылку.
link = encrypt_crypt(1, URL)
payload = link.split("/", 3)[3]
stripped = payload.lstrip("A")
if stripped != payload:
    check("ведущие 'A' потеряны (left-pad)",
          decrypt_happ_link("happ://crypt2/" + stripped) == URL)
else:
    check("ведущие 'A' потеряны (left-pad) [пропуск: выпал непустый случай]", True)

# ------------------------------------------------------- переопределение ключей

print("== пользовательские ключи ==")
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

own = rsa.generate_private_key(public_exponent=65537, key_size=2048)
own_der = own.private_bytes(
    serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
own_b64 = b64e(own_der)

keys_dir = Path("/home/z/my-project/sub_generator/data/happ_keys")
keys_dir.mkdir(parents=True, exist_ok=True)
try:
    (keys_dir / "crypt5_keys.json").write_text(
        '{"zztestmr": "' + own_b64 + '"}', encoding="utf-8")
    hd._reset_key_cache()
    keys = hd._crypt5_keys()
    check("пользовательский crypt5-ключ добавлен к встроенным",
          "zztestmr" in keys and len(keys) == 37)
    # Шифруем СВОИМ ключом (маркер zztestmr), расшифровываем модулем.
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    chacha_key = os.urandom(32)
    salt = rand_str(8, ALNUM).encode()
    rsa_value = bytes(chacha_key[i] ^ salt[i % 8] for i in range(32))
    rsa_ct = own.public_key().encrypt(
        bytes(hd._swap_pairs(b64e(rsa_value).encode())), padding.PKCS1v15())
    nonce = rand_str(12, ALNUM).encode()
    ct = ChaCha20Poly1305(chacha_key).encrypt(
        nonce, bytes(hd._swap_pairs(b64e(URL.encode()).encode())), None)
    url_b64 = b64e(ct)
    body = nonce + b"tA" + salt + str(len(url_b64)).encode() + b":" + url_b64.encode() + b64e(rsa_ct).encode()
    pre = b"zzte" + body + b"stmr"
    check("раунд-трип через пользовательский ключ",
          decrypt_happ_link("happ://crypt5/" + hd._block_pair_swap(pre).decode()) == URL)

    # pkcs1_keys.json переопределяет crypt (индекс 0).
    own2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    own2_b64 = b64e(own2.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (keys_dir / "pkcs1_keys.json").write_text('["' + own2_b64 + '"]', encoding="utf-8")
    hd._reset_key_cache()
    data, out = URL.encode(), b""
    for off in range(0, len(data), 2048 // 8 - 11):
        out += own2.public_key().encrypt(data[off:off + 2048 // 8 - 11], padding.PKCS1v15())
    check("pkcs1_keys.json переопределяет crypt", decrypt_happ_link("happ://crypt/" + b64e(out)) == URL)
finally:
    for name in ("crypt5_keys.json", "pkcs1_keys.json"):
        p = keys_dir / name
        if p.exists():
            p.unlink()
    hd._reset_key_cache()

# ------------------------------------------------------------- битая ссылка юзера

print("== битая ссылка пользователя (скопирована с потерей 2 симв.) ==")
user_link_path = Path("/home/z/my-project/scripts/user_happ_link.txt")
if user_link_path.exists():
    errs = []
    res = decrypt_happ_link(user_link_path.read_text().strip(), errors=errs)
    check("битая ссылка -> None (без исключения)", res is None)
    check("причина упоминает неполное копирование (префикс маркера известен)",
          any("скопирована не полностью" in e for e in errs), str(errs[:1]))

# ------------------------------------------------------------------ диспетчер

print("== диспетчер ==")
check("is_happ_link", is_happ_link("HAPP://crypt/x") and not is_happ_link("https://x"))
errs = []
check("неизвестная схема crypt6 -> None",
      decrypt_happ_link("happ://crypt6/abc", errors=errs) is None
      and any("crypt6" in e for e in errs))
check("не-happ ссылка -> None без ошибок", decrypt_happ_link("https://example.com") is None)
check("happ:// без payload -> None", decrypt_happ_link("happ://crypt5", errors=errs) is None)

# ------------------------------------------------------- интеграция с fetch

print("== _fetch_text интеграция ==")
import runtime.fetch as F
from io import BytesIO


class FakeResponse:
    def __init__(self, body: bytes):
        self._body = body
        self.headers = {"Content-Encoding": ""}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


captured = {}


def fake_urlopen(req, timeout=None, context=None):
    captured["url"] = req.full_url if hasattr(req, "full_url") else str(req)
    return FakeResponse(b"vless://uuid@1.2.3.4:443?security=tls#node1\nvless://uuid@5.6.7.8:443?#node2")


F.urlopen = fake_urlopen
F._CURL_CACHE["info"] = ("", False)     # транспортные фолбэки выключены
F._powershell_exe = lambda: ""          # (герметичность, как в test_fetch_unwrap)

logs: list[str] = []
link = encrypt_crypt5("https://sub.example.com/list.txt", salted=True)
body = F._fetch_text(link, timeout=2, log_sink=logs.append)
check("fetch: тело подписки получено по расшифрованному URL",
      "vless://uuid@1.2.3.4" in body and captured["url"] == "https://sub.example.com/list.txt")
check("fetch: лог содержит строку расшифровки",
      any("happ subscription decrypted: https://sub.example.com/list.txt" in s for s in logs))

try:
    F._fetch_text("happ://crypt5/!!битая!!", timeout=2, log_sink=None)
    check("fetch: битая happ-ссылка -> RuntimeError", False)
except RuntimeError as e:
    msg = str(e)
    check("fetch: битая happ-ссылка -> RuntimeError", "happ subscription decrypt failed" in msg)
    check("fetch: причина расшифровки в сообщении",
          len(msg.split(":", 1)) > 1 and len(msg.split(":", 1)[1].strip()) > 10, msg)

# Ссылка юзера в fetch — внятная ошибка, не «url error happ» без причин.
if user_link_path.exists():
    try:
        F._fetch_text(user_link_path.read_text().strip(), timeout=2, log_sink=None)
        check("fetch: юзерская битая ссылка -> RuntimeError", False)
    except RuntimeError as e:
        check("fetch: юзерская битая ссылка -> RuntimeError с причиной",
              "decrypt failed" in str(e) and ("скопирована" in str(e) or "маркер" in str(e)
              or "раскладка" in str(e) or "нестандартный" in str(e)), str(e)[:120])

# Вкладка «Импорт» должна ходить через _fetch_text (happ:// расшифровка +
# транспортная цепочка), а не голым urlopen — тот падал с «unknown url type:
# 'happ'» ещё до расшифровки (дефект 2026-09-19, «url error happ»).
import pathlib
_ip = pathlib.Path(__file__).resolve().parent.parent / "python" / "ui" / "pages" / "import_page.py"
if _ip.exists():
    _src = _ip.read_text(encoding="utf-8")
    check("import: страница импорта вызывает _fetch_text",
          "_fetch_text" in _src and "from xray_runtime import _fetch_text" in _src)
    check("import: страница импорта НЕ дергает urlopen напрямую",
          "urllib.request.urlopen" not in _src)

# --------------------------------------------------------------- встроенные ключи

print("== встроенные ключи ==")
from runtime.happ_keys import CRYPT5_KEYS_B64, PKCS1_KEYS_B64
check("4 ключа crypt..crypt4", len(PKCS1_KEYS_B64) == 4)
check("36 ключей crypt5 (маркер -> b64)", len(CRYPT5_KEYS_B64) == 36)
check("маркеры 8-символьные нижним регистром",
      all(len(m) == 8 and m.isalpha() and m.islower() for m in CRYPT5_KEYS_B64))
check("маркер vdfzfoff (ссылка юзера) в наборе", "vdfzfoff" in CRYPT5_KEYS_B64)

# --------------------------------------------------------------------- итог
print(f"\n=== happ crypt5: {PASS} PASS, {FAIL} FAIL ===")
sys.exit(1 if FAIL else 0)
