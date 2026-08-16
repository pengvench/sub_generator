"""Кэширование результатов проверок узлов.

Позволяет не перепроверять узлы, которые прошли тесты недавно.
Использует hash от URL узла как ключ и хранит:
- timestamp последней проверки
- результат (passed/failed)
- детали проверки (опционально)
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from subgen.config import DATA_DIR
from subgen.checker_thresholds import load_thresholds

_CACHE_PATH = DATA_DIR / "checker_cache.json"
_lock = threading.Lock()


@dataclass
class CacheEntry:
    """Запись кэша для одного узла."""
    
    url_hash: str
    timestamp: float  # unix timestamp
    passed: bool
    checker_type: str  # 'dpi', 'telegram', 'video', etc.
    details: dict = field(default_factory=dict)
    
    def is_valid(self, ttl_seconds: int) -> bool:
        """Проверить, не истёк ли срок действия записи."""
        return (time.time() - self.timestamp) < ttl_seconds
    
    def to_dict(self) -> dict:
        return {
            "url_hash": self.url_hash,
            "timestamp": self.timestamp,
            "passed": self.passed,
            "checker_type": self.checker_type,
            "details": self.details,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "CacheEntry":
        return cls(
            url_hash=data["url_hash"],
            timestamp=data["timestamp"],
            passed=data["passed"],
            checker_type=data["checker_type"],
            details=data.get("details", {}),
        )


class CheckerCache:
    """Кэш результатов проверок узлов."""
    
    def __init__(self, cache_path: Optional[Path] = None):
        self._cache_path = cache_path or _CACHE_PATH
        self._entries: dict[str, CacheEntry] = {}
        self._load()
    
    def _hash_url(self, url: str) -> str:
        """Создать hash от URL узла."""
        return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    
    def _load(self) -> None:
        """Загрузить кэш из файла."""
        try:
            if self._cache_path.exists():
                data = json.loads(self._cache_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._entries = {
                        k: CacheEntry.from_dict(v) for k, v in data.items()
                    }
        except Exception:
            self._entries = {}
    
    def _save(self) -> None:
        """Сохранить кэш в файл."""
        with _lock:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._cache_path.with_suffix(".json.tmp")
            data = {k: v.to_dict() for k, v in self._entries.items()}
            tmp.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            tmp.replace(self._cache_path)
    
    def get(
        self,
        url: str,
        checker_type: str,
    ) -> Optional[CacheEntry]:
        """Получить запись кэша для узла и типа проверки."""
        key = f"{checker_type}:{self._hash_url(url)}"
        entry = self._entries.get(key)
        if entry is None:
            return None
        
        thresholds = load_thresholds()
        ttl = thresholds.get("cache", {}).get("ttl_seconds", 3600)
        
        if not entry.is_valid(ttl):
            # Истёк срок действия — удаляем запись
            del self._entries[key]
            return None
        
        return entry
    
    def set(
        self,
        url: str,
        checker_type: str,
        passed: bool,
        details: Optional[dict] = None,
    ) -> None:
        """Добавить/обновить запись кэша."""
        key = f"{checker_type}:{self._hash_url(url)}"
        entry = CacheEntry(
            url_hash=self._hash_url(url),
            timestamp=time.time(),
            passed=passed,
            checker_type=checker_type,
            details=details or {},
        )
        self._entries[key] = entry
        
        # Ограничиваем размер кэша
        thresholds = load_thresholds()
        max_entries = thresholds.get("cache", {}).get("max_entries", 1000)
        if len(self._entries) > max_entries:
            # Удаляем самые старые записи
            sorted_entries = sorted(
                self._entries.items(),
                key=lambda x: x[1].timestamp,
            )
            for i in range(len(self._entries) - max_entries):
                del self._entries[sorted_entries[i][0]]
        
        self._save()
    
    def clear(self) -> None:
        """Очистить весь кэш."""
        with _lock:
            self._entries.clear()
            if self._cache_path.exists():
                self._cache_path.unlink()
    
    def cleanup_expired(self) -> int:
        """Удалить просроченные записи. Возвращает количество удалённых."""
        thresholds = load_thresholds()
        ttl = thresholds.get("cache", {}).get("ttl_seconds", 3600)
        
        expired_keys = [
            k for k, v in self._entries.items()
            if not v.is_valid(ttl)
        ]
        for key in expired_keys:
            del self._entries[key]
        
        if expired_keys:
            self._save()
        
        return len(expired_keys)
    
    def stats(self) -> dict[str, Any]:
        """Статистика кэша."""
        thresholds = load_thresholds()
        ttl = thresholds.get("cache", {}).get("ttl_seconds", 3600)
        
        now = time.time()
        valid_count = sum(
            1 for v in self._entries.values()
            if v.is_valid(ttl)
        )
        
        by_checker: dict[str, int] = {}
        for entry in self._entries.values():
            if entry.is_valid(ttl):
                by_checker[entry.checker_type] = by_checker.get(entry.checker_type, 0) + 1
        
        return {
            "total_entries": len(self._entries),
            "valid_entries": valid_count,
            "expired_entries": len(self._entries) - valid_count,
            "by_checker": by_checker,
            "ttl_seconds": ttl,
            "oldest_timestamp": min((v.timestamp for v in self._entries.values()), default=None),
            "newest_timestamp": max((v.timestamp for v in self._entries.values()), default=None),
        }


# Глобальный экземпляр кэша
_cache: Optional[CheckerCache] = None


def get_cache() -> CheckerCache:
    """Получить глобальный экземпляр кэша."""
    global _cache
    if _cache is None:
        _cache = CheckerCache()
    return _cache


def check_cached(
    url: str,
    checker_type: str,
) -> tuple[Optional[bool], Optional[CacheEntry]]:
    """Проверить кэш для узла.
    
    Возвращает (passed, entry) если запись найдена и валидна,
    или (None, None) если кэш отсутствует или устарел.
    """
    cache = get_cache()
    entry = cache.get(url, checker_type)
    if entry is not None:
        return entry.passed, entry
    return None, None


def cache_result(
    url: str,
    checker_type: str,
    passed: bool,
    details: Optional[dict] = None,
) -> None:
    """Сохранить результат проверки в кэш."""
    cache = get_cache()
    cache.set(url, checker_type, passed, details)


if __name__ == "__main__":
    # Тест кэша
    cache = get_cache()
    
    # Добавляем тестовые записи
    cache.set("vless://test1@example.com", "dpi", True, {"score": 85})
    cache.set("vless://test2@example.com", "dpi", False, {"reason": "timeout"})
    cache.set("vless://test1@example.com", "telegram", True, {"telegram_score": 75})
    
    # Проверяем
    passed, entry = check_cached("vless://test1@example.com", "dpi")
    print(f"Test1 DPI: passed={passed}, entry={entry}")
    
    passed, entry = check_cached("vless://test2@example.com", "dpi")
    print(f"Test2 DPI: passed={passed}, entry={entry}")
    
    # Статистика
    print(f"Stats: {cache.stats()}")
