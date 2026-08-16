"""Конфигурация порогов и параметров для проверок (checkers thresholds).

Этот файл содержит все пороги принятия решений, таймауты и параметры
для различных checkers. Значения можно менять без изменения кода checkers.

Формат: JSON с комментариями (поддерживается python jsonc parser или обычный JSON).
"""
import json
from pathlib import Path
from typing import Any

from subgen.config import DATA_DIR

_CHECKER_THRESHOLDS_PATH = DATA_DIR / "checker_thresholds.json"

# Значения по умолчанию для всех порогов
DEFAULT_THRESHOLDS = {
    # DPI-проверка (checkers/dpi.py)
    "dpi": {
        "timeout": 10.0,
        "accept_fraction": 0.5,  # доля целей для принятия узла
        "default_targets": ["instagram.com", "facebook.com", "x.com"],
        "require_siberian": False,  # siberian-проверка как обязательная
        "require_cidr": False,  # CIDR-whitelist как обязательная
    },
    
    # Активная DPI-проверка (checkers/dpi_active.py)
    "dpi_active": {
        "timeout": 4.0,
        "min_score": 0.6,  # минимальный robustness_score (0-1) для принятия
    },
    
    # Telegram-проверка (checkers/telegram_pro.py)
    "telegram": {
        "timeout": 5.0,
        "upload_bytes": 4 * 1024 * 1024,  # 4 МБ
        "download_bytes": 4 * 1024 * 1024,  # 4 МБ
        "upload_sample_sec": 3.0,
        "download_sample_sec": 3.0,
        "good_kbps": 2048.0,  # порог хорошей скорости
        "min_score": 60.0,  # минимальный telegram_score для принятия
        "weights": {
            "connect": 0.30,
            "auth": 0.30,
            "upload": 0.20,
            "download": 0.20,
        },
    },
    
    # Видео-проверка (checkers/video.py)
    "video": {
        "timeout": 5.0,
        "segment_timeout": 6.0,
        "segments_count": 20,
        "segment_bytes": 2 * 1024 * 1024,  # 2 МБ
        "max_timeouts": 4,  # допустимое число таймаутов
        "min_avg_kbps": 1024.0,  # ~8 Мбит/с
    },
    
    # CIDR/маскировка (checkers/cidr.py)
    "cidr": {
        "timeout": 10.0,
        "min_score": 50,  # минимум 50 из 100 для принятия
        "target_host": "www.google.com",
        "target_port": 443,
    },
    
    # Zapret-проверка (checkers/zapret.py)
    "zapret": {
        "timeout": 5.0,
        "max_targets": 8,
        "min_score": 0.75,  # доля успешных тестов
    },
    
    # Route-проверка (checkers/route.py)
    "route": {
        "timeout": 5.0,
        "probes": 5,
    },
    
    # Кэширование
    "cache": {
        "enabled": True,
        "ttl_seconds": 3600,  # кэш действителен 1 час
        "max_entries": 1000,  # максимум записей в кэше
    },
    
    # Initial Check (checkers/initial_check.py) - быстрая проверка доступности
    "initial_check": {
        "timeout": 3.0,  # строгий таймаут для быстрого отсева
        "check_url": "http://clients3.google.com/generate_204",
        "expected_status": 204,
    },
    
    # Параллелизация
    "parallel": {
        "enabled": True,
        "max_workers_per_node": 3,  # максимум параллельных тестов на один узел
    },
}


def load_thresholds() -> dict[str, Any]:
    """Загрузить пороги из checker_thresholds.json (с подстановкой дефолтов)."""
    thresholds = DEFAULT_THRESHOLDS.copy()
    try:
        if _CHECKER_THRESHOLDS_PATH.exists():
            data = json.loads(_CHECKER_THRESHOLDS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                # Merge на верхнем уровне
                for key, value in data.items():
                    if key in thresholds and isinstance(value, dict):
                        # Deep merge для вложенных dict
                        thresholds[key] = {**thresholds[key], **value}
                    else:
                        thresholds[key] = value
    except Exception:
        pass
    return thresholds


def save_thresholds(thresholds: dict[str, Any]) -> None:
    """Сохранить пороги в checker_thresholds.json."""
    _CHECKER_THRESHOLDS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _CHECKER_THRESHOLDS_PATH.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(thresholds, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tmp.replace(_CHECKER_THRESHOLDS_PATH)


def get_threshold(category: str, key: str, default: Any = None) -> Any:
    """Получить конкретный порог по категории и ключу."""
    thresholds = load_thresholds()
    return thresholds.get(category, {}).get(key, default)


def create_default_config() -> None:
    """Создать файл конфигурации с дефолтными значениями."""
    save_thresholds(DEFAULT_THRESHOLDS)
    print(f"Created default config at {_CHECKER_THRESHOLDS_PATH}")


if __name__ == "__main__":
    create_default_config()
