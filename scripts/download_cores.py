#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Обновление ядер xray / sing-box для ПК-сборки SubGenerator (Windows).

Скачивает свежие релизы с GitHub и кладёт бинарники в bin/ под именами
xray.exe / sing-box.exe (пути, которые ищет xray_runtime._resolve_binary).

Использование (из корня репозитория или из scripts/):
    python scripts/download_cores.py                      # последние релизы
    python scripts/download_cores.py 26.3.27 1.13.16      # конкретные версии

Требуется Python 3.8+ (stdlib only).
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BIN_DIR = ROOT / "bin"
VERSIONS_FILE = BIN_DIR / "CORE_VERSIONS.txt"

XRAY_REPO = "XTLS/Xray-core"
SINGBOX_REPO = "SagerNet/sing-box"

GH_API = "https://api.github.com/repos/{repo}/releases/latest"
GH_DL = "https://github.com/{repo}/releases/download/{tag}/{asset}"


def http_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "subgen-core-fetch"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def download(url: str, dest: Path) -> None:
    print(f"скачиваю {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "subgen-core-fetch"})
    with urllib.request.urlopen(req, timeout=600) as resp, open(dest, "wb") as out:
        shutil.copyfileobj(resp, out)
    print(f"  -> {dest} ({dest.stat().st_size // 1024 // 1024} МБ)")


def latest_tag(repo: str) -> str:
    data = http_json(GH_API.format(repo=repo))
    return str(data["tag_name"])


def fetch_xray(version: str, tmp: Path) -> tuple[Path, str]:
    """Windows-64 сборка Xray-core (xray.exe внутри zip)."""
    tag = f"v{version}" if not version.startswith("v") else version
    asset = "Xray-windows-64.zip"
    url = GH_DL.format(repo=XRAY_REPO, tag=tag, asset=asset)
    archive = tmp / "xray.zip"
    download(url, archive)
    with zipfile.ZipFile(archive) as z:
        z.extract("xray.exe", tmp)
    return tmp / "xray.exe", tag


def fetch_singbox(version: str, tmp: Path) -> tuple[Path, str]:
    """Windows-amd64 сборка sing-box (sing-box.exe внутри zip)."""
    tag = f"v{version}" if not version.startswith("v") else version
    asset = f"sing-box-{version}-windows-amd64.zip"
    url = GH_DL.format(repo=SINGBOX_REPO, tag=tag, asset=asset)
    archive = tmp / "singbox.zip"
    download(url, archive)
    with zipfile.ZipFile(archive) as z:
        name = next(n for n in z.namelist() if n.endswith("sing-box.exe"))
        z.extract(name, tmp)
        extracted = tmp / name
    return extracted, tag


def main(argv: list[str]) -> int:
    xray_version = argv[0] if len(argv) > 0 else None
    singbox_version = argv[1] if len(argv) > 1 else None

    if xray_version is None:
        print("определяю последний Xray-core…")
        xray_version = latest_tag(XRAY_REPO).lstrip("v")
    if singbox_version is None:
        print("определяю последний sing-box…")
        singbox_version = latest_tag(SINGBOX_REPO).lstrip("v")

    BIN_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="subgen-cores-") as td:
        tmp = Path(td)
        xray_bin, xray_tag = fetch_xray(xray_version, tmp)
        sing_bin, sing_tag = fetch_singbox(singbox_version, tmp)

        shutil.copy2(xray_bin, BIN_DIR / "xray.exe")
        shutil.copy2(sing_bin, BIN_DIR / "sing-box.exe")

    VERSIONS_FILE.write_text(
        f"Xray-core {xray_tag} https://github.com/XTLS/Xray-core/releases/tag/{xray_tag}\n"
        f"sing-box {sing_tag} https://github.com/SagerNet/sing-box/releases/tag/{sing_tag}\n",
        encoding="utf-8",
    )
    print(f"готово: {BIN_DIR / 'xray.exe'}, {BIN_DIR / 'sing-box.exe'}")
    print(f"версии записаны в {VERSIONS_FILE}")
    print("теперь пересоберите релиз: build_release.bat (из корня репозитория)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
