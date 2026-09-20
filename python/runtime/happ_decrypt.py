"""Расшифровка happ://cryptN/ ссылок.

Поддерживаются все схемы клиента Happ: crypt, crypt2, crypt3, crypt4 и
crypt5 (в обоих вариантах раскладки тела — legacy и salted).

  crypt..crypt4 — RSA PKCS#1 v1.5, БЛОЧНОЕ шифрование (блок = размер ключа,
      длинные URL разбиты на несколько блоков). Ключи вшиты в каждый
      дистрибутив клиента Happ (см. runtime/happ_keys.py).
  crypt5 — гибридная схема: 8-символьный маркер (первые 4 + последние 4
      символа payload после block-pair-swap) выбирает RSA-4096 PKCS#8-ключ;
      расшифрованный RSA-блоб несёт 32-байтовый ключ ChaCha20-Poly1305,
      которым расшифровывается само тело ссылки. Два layout'а тела:
      legacy  — nonce(12) + цифры длины + разделитель + url-b64 + rsa-b64;
      salted  — nonce(12) + тег(2) + соль(8) + ... (ключ = rsa_value XOR
      повторённая соль). Цифра на body[12] → legacy, буква → salted;
      пробуем оба порядка.

Встроенные ключи переопределяются/расширяются пользовательскими файлами
(см. data/happ_keys/README.md): pkcs1_keys.json (список, по индексу) и
crypt5_keys.json (словарь маркер → ключ). Зависимость cryptography
импортируется ЛЕНИВО — без неё модуль импортируется, а ошибка возникает
только при попытке расшифровать happ://-ссылку.

Алгоритм восстановлен по открытым реализациям экосистемы (hpwnr,
Happ-converter) и воспроизведён криптографически (RSA + Poly1305-тег).
Подключается из runtime.fetch._fetch_text: happ://-источник расшифровывается
в обычный https:// URL и дальше идёт по стандартному конвейеру (зеркала,
транспортная цепочка urlopen → curl → PowerShell).
"""
from __future__ import annotations

import base64
import logging
import sys
from pathlib import Path

from .happ_keys import CRYPT5_KEYS_B64, PKCS1_KEYS_B64

logger = logging.getLogger(__name__)

# Схема ссылки -> индекс ключа PKCS1 (happ_keys.PKCS1_KEYS_B64).
_SCHEME_ORDINALS = {"crypt": 0, "crypt2": 1, "crypt3": 2, "crypt4": 3}


def _keys_dir() -> Path:
    """Каталог ключей: из исходников — <repo>/data/happ_keys, из exe — рядом с exe."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "data" / "happ_keys"
    return Path(__file__).resolve().parent.parent.parent / "data" / "happ_keys"


def _report(errors: list[str] | None, message: str) -> None:
    """Причина неудачи — и в лог, и (опционально) в список для вызывающего кода."""
    logger.warning("happ: %s", message)
    if errors is not None and message not in errors:
        errors.append(message)


# --------------------------------------------------------------------- base64

def _b64_decode(text: str) -> bytes:
    """Гибкий base64: std/url-safe алфавит, пробелы, произвольный padding.

    Ссылки бывают скопированы с потерянным padding, url-safe заменами и
    переносами строк — _fetch_text не должен падать раньше расшифровки.
    """
    clean = "".join(ch for ch in str(text or "") if ch not in " \n\r\t")
    clean = clean.replace("-", "+").replace("_", "/")
    for variant in (clean, clean.rstrip("=")):
        padded = variant + "=" * (-len(variant) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                return decoder(padded)
            except Exception:
                continue
    raise ValueError(f"invalid base64: {str(text)[:40]!r}...")


# ------------------------------------------------------------ перестановки

def _swap_pairs(data: bytes) -> bytes:
    """Обмен соседних байтов парами (ABCD -> BADC); самообратная."""
    buf = bytearray(data)
    for i in range(0, len(buf) - 1, 2):
        buf[i], buf[i + 1] = buf[i + 1], buf[i]
    return bytes(buf)


def _block_pair_swap(data: bytes) -> bytes:
    """Обмен половин каждого 4-байтового блока (ABCD -> CDAB); самообратная."""
    buf = bytearray(data)
    full = len(buf) - len(buf) % 4
    for i in range(0, full, 4):
        buf[i], buf[i + 2] = buf[i + 2], buf[i]
        buf[i + 1], buf[i + 3] = buf[i + 3], buf[i + 1]
    return bytes(buf)


# --------------------------------------------------------------------- ключи

# Кеш распарсенных ключей (RSA-4096 × 36 парсится ~0.3с — один раз).
_pkcs1_cache: list | None = None
_crypt5_cache: dict | None = None


def _load_private_key(encoded: str):
    """PKCS#1/PKCS#8 DER (base64) -> приватный ключ (ленивый импорт cryptography)."""
    try:
        from cryptography.hazmat.primitives.serialization import load_der_private_key
    except ImportError as exc:
        raise RuntimeError(
            "happ: пакет 'cryptography' не установлен (pip install cryptography)"
        ) from exc
    der = base64.b64decode(encoded)
    return load_der_private_key(der, password=None)


def _pkcs1_keys() -> list:
    """Ключи crypt..crypt4: встроенные + переопределение pkcs1_keys.json."""
    global _pkcs1_cache
    if _pkcs1_cache is not None:
        return _pkcs1_cache
    keys_b64: list[str] = list(PKCS1_KEYS_B64)
    path = _keys_dir() / "pkcs1_keys.json"
    if path.exists():
        try:
            import json
            user_keys = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(user_keys, list):
                for i, key in enumerate(user_keys):
                    if isinstance(key, str) and key.strip():
                        if i < len(keys_b64):
                            keys_b64[i] = key.strip()
                        else:
                            keys_b64.append(key.strip())
                logger.info("happ: применены пользовательские ключи %s", path.name)
        except Exception as e:
            logger.warning("happ: cannot load user keys: %s", e)
    _pkcs1_cache = [_load_private_key(k) for k in keys_b64]
    return _pkcs1_cache


def _crypt5_keys() -> dict:
    """Ключи crypt5: встроенные (маркер → ключ) + расширение crypt5_keys.json."""
    global _crypt5_cache
    if _crypt5_cache is not None:
        return _crypt5_cache
    keys_b64: dict[str, str] = dict(CRYPT5_KEYS_B64)
    path = _keys_dir() / "crypt5_keys.json"
    if path.exists():
        try:
            import json
            user_keys = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(user_keys, dict):
                for marker, key in user_keys.items():
                    if isinstance(marker, str) and isinstance(key, str) and key.strip():
                        keys_b64[marker.strip()] = key.strip()
                logger.info("happ: применены пользовательские crypt5-ключи %s", path.name)
        except Exception as e:
            logger.warning("happ: cannot load user crypt5 keys: %s", e)
    _crypt5_cache = {marker: _load_private_key(key) for marker, key in keys_b64.items()}
    return _crypt5_cache


def _reset_key_cache() -> None:
    """Сброс кеша ключей (для тестов, после записи пользовательских файлов)."""
    global _pkcs1_cache, _crypt5_cache
    _pkcs1_cache = None
    _crypt5_cache = None


# ------------------------------------------------------------------ crypt..4

def _rsa_decrypt_block(key, cipher: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import padding
    return key.decrypt(cipher, padding.PKCS1v15())


def _decrypt_crypt(ordinal: int, payload: str, errors: list[str]) -> str | None:
    """crypt..crypt4: RSA PKCS#1 v1.5 блоками по размеру ключа.

    Длинные plaintext-URL Happ шифрует несколькими блоками; выравнивание
    ciphertext может быть потеряно при копировании — тогда первый неполный
    блок дополняется нулями слева (RSA-числа ведущие нули игнорируют).
    """
    try:
        keys = _pkcs1_keys()
        if ordinal >= len(keys):
            _report(errors, f"нет ключа для схемы (индекс {ordinal}) — см. data/happ_keys/")
            return None
        key = keys[ordinal]
        cipher = _b64_decode(payload)
        if not cipher:
            _report(errors, "пустой шифртекст")
            return None
        block_size = key.key_size // 8
        if len(cipher) % block_size:
            cipher = b"\x00" * (block_size - len(cipher) % block_size) + cipher
        chunks: list[bytes] = []
        for offset in range(0, len(cipher), block_size):
            chunks.append(_rsa_decrypt_block(key, cipher[offset:offset + block_size]))
        url = b"".join(chunks).decode("utf-8", errors="replace").strip()
    except RuntimeError:
        raise
    except Exception as e:
        _report(errors, f"RSA-расшифровка не удалась: {type(e).__name__}")
        return None
    if url.startswith("http"):
        return url
    _report(errors, f"расшифрованный текст не похож на URL: {url[:40]!r}")
    return None


# --------------------------------------------------------------------- crypt5

def _decrypt_crypt5_body(body: bytes, key, salted: bool) -> str:
    """Одна раскладка тела crypt5; бросает исключение при несоответствии."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    nonce = body[:12]
    if salted:
        if len(body) < 22:
            raise ValueError("salted header too short")
        salt = body[14:22]
        rest = body[22:]
    else:
        salt = None
        rest = body[12:]

    # Цифры = длина url-b64 сегмента, затем разделитель, затем сам сегмент и RSA-блоб.
    digit_count = 0
    while digit_count < len(rest) and chr(rest[digit_count]).isdigit():
        digit_count += 1
    if digit_count == 0:
        raise ValueError("segment length missing")
    seg_len = int(rest[:digit_count])
    packed = rest[digit_count:]
    if len(packed) < 1 + seg_len:
        raise ValueError("segment truncated")
    url_b64 = packed[1:1 + seg_len]
    rsa_b64 = packed[1 + seg_len:]

    rsa_plain = _rsa_decrypt_block(key, _b64_decode(rsa_b64.decode("ascii", errors="replace")))
    # Классический формат: RSA-блоб несёт 44-символьный base64-текст ключа.
    # Бинарные данные другого объёма = нестандартный генератор (проверено:
    # свежие официальные клиенты Happ такие ссылки тоже не принимают).
    if not all(32 <= b < 127 for b in rsa_plain) or len(rsa_plain) > 512:
        raise ValueError(
            f"RSA-блок содержит бинарные данные ({len(rsa_plain)} байт вместо "
            f"44-символьного ключа) — нестандартный формат ссылки"
        )
    rsa_value = _b64_decode(_swap_pairs(rsa_plain).decode("ascii", errors="replace"))
    if len(rsa_value) != 32:
        raise ValueError(f"chacha key length {len(rsa_value)} != 32")

    if salt is not None:
        chacha_key = bytes(rsa_value[i] ^ salt[i % 8] for i in range(32))
    else:
        chacha_key = rsa_value

    intermediate = ChaCha20Poly1305(chacha_key).decrypt(nonce, _b64_decode(url_b64.decode("ascii", errors="replace")), None)
    plain = _b64_decode(_swap_pairs(intermediate).decode("ascii", errors="replace"))
    return plain.decode("utf-8", errors="replace").strip()


def _decrypt_crypt5(payload: str, errors: list[str]) -> str | None:
    """crypt5: маркер → RSA-ключ → ChaCha20-ключ → тело → URL."""
    try:
        shuffled = _block_pair_swap(payload.encode("utf-8", errors="replace"))
        if len(shuffled) < 8 + 13:
            _report(errors, "crypt5: payload слишком короткий")
            return None
        n = len(shuffled)
        marker = shuffled[:4].decode("ascii", errors="replace") + shuffled[n - 4:n].decode("ascii", errors="replace")
        keys = _crypt5_keys()
        key = keys.get(marker)
        if key is None:
            # Известный ПРЕФИКС маркера (первые 4 символа извлекаются из головы
            # payload и не зависят от битого хвоста): ссылка почти наверняка
            # скопирована не полностью — хвост не сходится с маркером.
            prefix_matches = [m for m in keys if m[:4] == marker[:4]]
            if prefix_matches:
                _report(
                    errors,
                    f"crypt5: маркер {marker!r} неизвестен, но префикс совпадает с "
                    f"{prefix_matches[0]!r} — ссылка скопирована не полностью/с потерей "
                    f"символов (ссылка новее ключей маловероятна)",
                )
            else:
                _report(
                    errors,
                    f"crypt5: неизвестный маркер {marker!r} (ссылка новее встроенных ключей — "
                    f"добавьте ключ в data/happ_keys/crypt5_keys.json)",
                )
            return None
        body = shuffled[4:n - 4]
        # Цифра на body[12] → legacy-раскладка, буква → salted; обе пробуем.
        prefer_salted = len(body) > 12 and not chr(body[12]).isdigit()
        layouts = (True, False) if prefer_salted else (False, True)
        layout_errors: list[str] = []
        for salted in layouts:
            try:
                url = _decrypt_crypt5_body(body, key, salted)
            except Exception as e:
                # Причина конкретной раскладки (бинарный RSA-блоб, битый тег
                # Poly1305 и т.д.) ценнее безликого «не сошлась» — собираем.
                layout_errors.append(f"{'salted' if salted else 'legacy'}: {e}")
                continue
            if url.startswith("http"):
                return url
            _report(errors, f"crypt5: расшифрованный текст не похож на URL: {url[:40]!r}")
            return None
        detail = layout_errors[0] if len(layout_errors) == 1 else "; ".join(layout_errors)
        _report(errors, f"crypt5: ни одна раскладка тела не сошлась ({detail})")
        return None
    except RuntimeError:
        raise
    except Exception as e:
        _report(errors, f"crypt5: {type(e).__name__}: {e}")
        return None


# ------------------------------------------------------------------ диспетчер

def decrypt_happ_link(link: str, *, errors: list[str] | None = None) -> str | None:
    """happ://cryptN/<payload> -> обычный https:// URL (или None + причина).

    Причина неудачи пишется в лог и, если передан список errors, добавляется
    в него (первый элемент попадает в сообщение об ошибке конвейера).
    """
    link = str(link or "").strip()
    if not link.lower().startswith("happ://"):
        return None
    path = link[7:]
    parts = path.split("/", 1)
    if len(parts) != 2 or not parts[1].strip():
        if errors is not None:
            _report(errors, "happ: ссылка без payload")
        return None
    scheme = parts[0].strip().lower()
    payload = parts[1].strip()
    err: list[str] = errors if errors is not None else []
    if scheme == "crypt5":
        return _decrypt_crypt5(payload, err)
    if scheme in _SCHEME_ORDINALS:
        return _decrypt_crypt(_SCHEME_ORDINALS[scheme], payload, err)
    _report(err, f"happ: неподдерживаемая схема {scheme!r} (поддерживаются crypt..crypt5)")
    return None


def is_happ_link(text: str) -> bool:
    return str(text or "").strip().lower().startswith("happ://")
