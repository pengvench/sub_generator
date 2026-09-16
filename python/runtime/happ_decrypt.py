"""Расшифровка happ://cryptN/ ссылок.

Поддержка crypt, crypt2, crypt3, crypt4.
Ключи RSA лежат в data/happ_keys/pkcs1_keys.json (см. data/happ_keys/README.md).

Восстановлено (было осиротевшим): подключается из runtime.fetch._fetch_text —
если источник подписки начинается с happ://, ссылка расшифровывается в
обычный https:// URL и дальше идёт по стандартному конвейеру.
Зависимость cryptography импортируется ЛЕНИВО — без неё модуль импортируется,
а ошибка возникает только при попытке расшифровать happ://-ссылку.
"""
from __future__ import annotations

import base64
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def _keys_dir() -> Path:
    """Каталог ключей: из исходников — <repo>/data/happ_keys, из exe — рядом с exe."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "data" / "happ_keys"
    return Path(__file__).resolve().parent.parent.parent / "data" / "happ_keys"


_pkcs1_keys: list[str] | None = None


def _load_pkcs1_keys() -> list[str]:
    global _pkcs1_keys
    if _pkcs1_keys is not None:
        return _pkcs1_keys
    path = _keys_dir() / "pkcs1_keys.json"
    if not path.exists():
        logger.warning("happ: pkcs1_keys.json not found")
        return []
    try:
        _pkcs1_keys = json.loads(path.read_text(encoding="utf-8"))
        return _pkcs1_keys
    except Exception as e:
        logger.warning(f"happ: cannot load keys: {e}")
        return []


def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _decrypt_rsa_pkcs1(cipher: bytes, key_b64: str) -> bytes:
    # Ленивый импорт: cryptography — опциональная зависимость (нужна ТОЛЬКО
    # для happ-подписок). Без неё весь остальной проект работает.
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        from cryptography.hazmat.backends import default_backend
    except ImportError as exc:
        raise RuntimeError(
            "happ: пакет 'cryptography' не установлен (pip install cryptography)"
        ) from exc
    key_der = base64.b64decode(key_b64)
    private_key = load_der_private_key(key_der, password=None, backend=default_backend())
    key_size = private_key.key_size // 8
    if len(cipher) < key_size:
        cipher = b"\x00" * (key_size - len(cipher)) + cipher
    elif len(cipher) > key_size:
        cipher = cipher[:key_size]
    return private_key.decrypt(cipher, padding.PKCS1v15())


def decrypt_happ_link(link: str) -> str | None:
    link = link.strip()
    if not link.startswith("happ://"):
        return None
    path = link[7:]
    parts = path.split("/", 1)
    if len(parts) != 2:
        return None
    scheme = parts[0]
    payload = parts[1].strip()
    scheme_map = {"crypt": 0, "crypt2": 1, "crypt3": 2, "crypt4": 3}
    if scheme not in scheme_map:
        logger.warning(f"happ: unsupported scheme '{scheme}'")
        return None
    ordinal = scheme_map[scheme]
    keys = _load_pkcs1_keys()
    if ordinal >= len(keys):
        return None
    try:
        cipher = _b64url_decode(payload)
        plain = _decrypt_rsa_pkcs1(cipher, keys[ordinal])
        url = plain.decode("utf-8", errors="replace").strip()
        if url.startswith("http"):
            return url
        return None
    except Exception as e:
        logger.warning(f"happ: decrypt error: {e}")
        return None


def is_happ_link(text: str) -> bool:
    return str(text or "").strip().lower().startswith("happ://")
