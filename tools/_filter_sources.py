"""Фильтрация sources.txt: оставить только подписки, отдавшие хотя бы один конфиг,
прошедший первый пинг-тест.

Критерий "прошёл пинг":
  - узел в xray_working.json (прошёл полную проверку, включая пинг), ИЛИ
  - узел в xray_rejected.json с latency_ms не None (отклонён на стресс-тесте,
    а не на пинге).

Standalone: использует только стандартную библиотеку Python.
Пути можно передать аргументами командной строки (по умолчанию — рядом со скриптом).

Примеры:
  python _filter_sources.py
  python _filter_sources.py --sources sources.txt --working xray_working.json --rejected xray_rejected.json
"""
import argparse
import json
import sys
from pathlib import Path


def load_nodes(path: Path) -> list:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def norm(u: str) -> str:
    """Нормализация URL: убираем хвостовые слэши для сравнения."""
    return u.rstrip("/")


def app_dir() -> Path:
    """Директория приложения: рядом с .exe (PyInstaller) или рядом со скриптом."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Отфильтровать sources.txt, оставив только подписки, "
                    "отдавшие хотя бы один конфиг, прошедший первый пинг-тест."
    )
    here = app_dir()

    parser.add_argument("--sources", default=str(here / "sources.txt"),
                        help="Путь к sources.txt (по умолчанию рядом со скриптом)")
    parser.add_argument("--working", default=str(here / "xray_working.json"),
                        help="Путь к xray_working.json")
    parser.add_argument("--rejected", default=str(here / "xray_rejected.json"),
                        help="Путь к xray_rejected.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="Не перезаписывать sources.txt, только показать статистику")
    parser.add_argument("--force", action="store_true",
                        help="Перезаписать sources.txt, даже если не совпало ни одной подписки")
    args = parser.parse_args(argv)

    sources_path = Path(args.sources)
    working_path = Path(args.working)
    rejected_path = Path(args.rejected)

    if not working_path.exists():
        print(f"Ошибка: не найден файл {working_path}", file=sys.stderr)
        return 1
    if not rejected_path.exists():
        print(f"Ошибка: не найден файл {rejected_path}", file=sys.stderr)
        return 1
    if not sources_path.exists():
        print(f"Ошибка: не найден файл {sources_path}", file=sys.stderr)
        return 1

    working = load_nodes(working_path)
    rejected = load_nodes(rejected_path)

    good_sources: set[str] = set()

    for node in working:
        src = node.get("source")
        if src:
            good_sources.add(src)

    for node in rejected:
        if node.get("latency_ms") is not None:
            src = node.get("source")
            if src:
                good_sources.add(src)

    good_norm = {norm(s) for s in good_sources}

    with open(sources_path, encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]

    kept = [ln for ln in lines if norm(ln) in good_norm]
    removed = [ln for ln in lines if norm(ln) not in good_norm]

    # Защита от массовой отбраковки: если xray_working.json/xray_rejected.json —
    # старый кеш (например, от прогона с --limit или с другим набором подписок),
    # в нём просто нет источников из текущего sources.txt. Перезаписывать файл
    # (и фактически вычищать его) можно только явно через --force.
    mass_removal = lines and len(kept) == 0
    if not args.dry_run and mass_removal and not args.force:
        print(
            "ВНИМАНИЕ: ни одна подписка из sources.txt не найдена в результатах проверки.",
            file=sys.stderr,
        )
        print(
            "Возможно, xray_working.json/xray_rejected.json — это кеш от прогона с другим "
            "набором подписок или с --limit (в кеш попадают только источники проверенных "
            "узлов). Файл НЕ изменён.",
            file=sys.stderr,
        )
        print(
            "Чтобы всё же перезаписать sources.txt, запустите с флагом --force.",
            file=sys.stderr,
        )
        print()
    elif not args.dry_run:
        with open(sources_path, "w", encoding="utf-8") as f:
            f.write("\n".join(kept) + ("\n" if kept else ""))

    print(f"Всего подписок в sources.txt: {len(lines)}")
    print(f"Оставлено (дали >=1 конфиг, прошёл пинг): {len(kept)}")
    print(f"Убрано (мусорных): {len(removed)}")
    print(f"Уникальных источников, давших конфиг: {len(good_sources)}")
    if args.dry_run:
        print("(dry-run: файл не изменён)")
    if not args.dry_run and mass_removal and not args.force:
        print("(файл НЕ изменён: защита от массовой отбраковки)")
    print("\n--- Убранные подписки ---")
    for u in removed:
        print(u)

    return 0


if __name__ == "__main__":
    sys.exit(main())
