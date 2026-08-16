"""Константы и базовые настройки проекта sub_generator.

Все пути к данным — в data/, которая создаётся автоматически.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path


def _app_root() -> Path:
    """Корень приложения.

    При запуске из собранного PyInstaller-.exe — каталог рядом с exe
    (там лежат sources.txt, data/, bin/). При запуске из исходников —
    корень проекта (каталог, где лежат xray_runtime.py, bin/, checkers/).
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


# Корень проекта/приложения (каталог, где лежат xray_runtime.py, bin/, checkers/).
ROOT = _app_root()

# Единая папка для всех результатов (кеш, репорты, подписки, логи),
# чтобы не мусорить в корне проекта.
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Файл списка подписок по умолчанию (по строке на URL).
DEFAULT_SOURCES_FILE = ROOT / "sources.txt"



# --------------------------------------------------------------------------
# Описание подписки (добавляется в начало как комментарий)
# --------------------------------------------------------------------------
SUBSCRIPTION_DESCRIPTION = (
    "# ТГ канал автора: https://t.me/peppe_poppo\n"
    "# Сайт проекта: https://tetta-prod.ru\n"
)


# --------------------------------------------------------------------------
# Crypt encoding (простая XOR-обфускация)
# --------------------------------------------------------------------------
_CRYPT_KEY = b"mtproxy_autoswitch_key_2024"


def crypt_encode(data: str, key: bytes = _CRYPT_KEY) -> str:
    """Зашифровать данные с помощью XOR и вернуть base64-строку."""
    data_bytes = data.encode("utf-8")
    key_len = len(key)
    encrypted = bytes(data_bytes[i] ^ key[i % key_len] for i in range(len(data_bytes)))
    return base64.b64encode(encrypted).decode("ascii")


def crypt_decode(encoded: str, key: bytes = _CRYPT_KEY) -> str:
    """Расшифровать данные из base64 с помощью XOR."""
    encrypted = base64.b64decode(encoded.encode("ascii"))
    key_len = len(key)
    decrypted = bytes(encrypted[i] ^ key[i % key_len] for i in range(len(encrypted)))
    return decrypted.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Geoip
# --------------------------------------------------------------------------
# https://api.ip.sb/geoip — лимит 100 запросов/мин (до 5/сек) на бесплатном тарифе.
GEOIP_API = "https://api.ip.sb/geoip/{ip}"
GEOIP_TIMEOUT_SEC = 6.0
GEOIP_MAX_RATE_PER_SEC = 4.5  # чуть ниже лимита 5/сек, чтобы не упереться в rate limit
GEOIP_FALLBACK_FLAG = ""
GEOIP_FALLBACK_CODE = "??"

# Эмодзи-флаги: подмножество самых частых стран. Полную таблицу можно
# расширить, но на практике достаточно основных.
FLAG_EMOJI: dict[str, str] = {
    "RU": "\U0001F1F7\U0001F1FA", "US": "\U0001F1FA\U0001F1F8",
    "GB": "\U0001F1EC\U0001F1E7", "DE": "\U0001F1E9\U0001F1EA",
    "FR": "\U0001F1EB\U0001F1F7",
    "NL": "\U0001F1F3\U0001F1F1", "SE": "\U0001F1F8\U0001F1EA",
    "NO": "\U0001F1F3\U0001F1F4", "FI": "\U0001F1EB\U0001F1EE",
    "DK": "\U0001F1E9\U0001F1F0",
    "PL": "\U0001F1F5\U0001F1F1", "CZ": "\U0001F1E8\U0001F1FF",
    "UA": "\U0001F1FA\U0001F1E6", "BY": "\U0001F1E7\U0001F1FE",
    "KZ": "\U0001F1F0\U0001F1FF",
    "EE": "\U0001F1EA\U0001F1EA", "LV": "\U0001F1F1\U0001F1FB",
    "LT": "\U0001F1F1\U0001F1F9", "MD": "\U0001F1F2\U0001F1E9",
    "RO": "\U0001F1F7\U0001F1F4",
    "BG": "\U0001F1E7\U0001F1EC", "HU": "\U0001F1ED\U0001F1FA",
    "AT": "\U0001F1E6\U0001F1F9", "CH": "\U0001F1E8\U0001F1ED",
    "BE": "\U0001F1E7\U0001F1EA",
    "ES": "\U0001F1EA\U0001F1F8", "PT": "\U0001F1F5\U0001F1F9",
    "IT": "\U0001F1EE\U0001F1F9", "GR": "\U0001F1EC\U0001F1F7",
    "TR": "\U0001F1F9\U0001F1F7",
    "IL": "\U0001F1EE\U0001F1F1", "AE": "\U0001F1E6\U0001F1EA",
    "SA": "\U0001F1F8\U0001F1E6", "IN": "\U0001F1EE\U0001F1F3",
    "SG": "\U0001F1F8\U0001F1EC",
    "JP": "\U0001F1EF\U0001F1F5", "KR": "\U0001F1F0\U0001F1F7",
    "CN": "\U0001F1E8\U0001F1F3", "HK": "\U0001F1ED\U0001F1F0",
    "TW": "\U0001F1F9\U0001F1FC",
    "TH": "\U0001F1F9\U0001F1ED", "VN": "\U0001F1FB\U0001F1F3",
    "MY": "\U0001F1F2\U0001F1FE", "ID": "\U0001F1EE\U0001F1E9",
    "PH": "\U0001F1F5\U0001F1ED",
    "AU": "\U0001F1E6\U0001F1FA", "NZ": "\U0001F1F3\U0001F1FF",
    "CA": "\U0001F1E8\U0001F1E6", "MX": "\U0001F1F2\U0001F1FD",
    "BR": "\U0001F1E7\U0001F1F7",
    "AR": "\U0001F1E6\U0001F1F7", "CL": "\U0001F1E8\U0001F1F1",
    "CO": "\U0001F1E8\U0001F1F4", "PE": "\U0001F1F5\U0001F1EA",
    "VE": "\U0001F1FB\U0001F1EA",
    "ZA": "\U0001F1FF\U0001F1E6", "EG": "\U0001F1EA\U0001F1EC",
    "NG": "\U0001F1F3\U0001F1EC", "KE": "\U0001F1F0\U0001F1EA",
    "MA": "\U0001F1F2\U0001F1E6",
    "GH": "\U0001F1EC\U0001F1ED", "IR": "\U0001F1EE\U0001F1F7",
    "IQ": "\U0001F1EE\U0001F1F6", "PK": "\U0001F1F5\U0001F1F0",
    "BD": "\U0001F1E7\U0001F1E9",
    "UZ": "\U0001F1FA\U0001F1FF", "AM": "\U0001F1E6\U0001F1F2",
    "AZ": "\U0001F1E6\U0001F1FF", "GE": "\U0001F1EC\U0001F1EA",
    "MN": "\U0001F1F2\U0001F1F3",
    "JO": "\U0001F1EF\U0001F1F4", "LB": "\U0001F1F1\U0001F1E7",
    "QA": "\U0001F1F6\U0001F1E6", "KW": "\U0001F1F0\U0001F1FC",
    "OM": "\U0001F1F4\U0001F1F2",
    "CR": "\U0001F1E8\U0001F1F7", "PA": "\U0001F1F5\U0001F1E6",
    "DO": "\U0001F1E9\U0001F1F4", "CU": "\U0001F1E8\U0001F1FA",
    "HT": "\U0001F1ED\U0001F1F9",
    "UY": "\U0001F1FA\U0001F1FE", "PY": "\U0001F1F5\U0001F1FE",
    "BO": "\U0001F1E7\U0001F1F4", "EC": "\U0001F1EA\U0001F1E8",
    "GT": "\U0001F1EC\U0001F1F9",
    "HN": "\U0001F1ED\U0001F1F3", "SV": "\U0001F1F8\U0001F1FB",
    "NI": "\U0001F1F3\U0001F1EE", "PR": "\U0001F1F5\U0001F1F7",
}
