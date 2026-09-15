"""Расшифровка happ://cryptN/ ссылок.

Поддержка crypt, crypt2, crypt3, crypt4.
Ключи RSA лежат в data/happ_keys/.
"""
from __future__ import annotations

import base64
import json
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

_KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "happ_keys"
_pkcs1_keys: list[str] | None = None


def _load_pkcs1_keys() -> list[str]:
    global _pkcs1_keys
    if _pkcs1_keys is not None:
        return _pkcs1_keys
    path = _KEYS_DIR / "pkcs1_keys.json"
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
    return text.strip().lower().startswith("happ://")
