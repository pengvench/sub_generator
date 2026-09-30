#!/usr/bin/env python3
"""v22: GUI-интеграция SNI-категоризации (БС/ЧС/серый/фейк/none).

Проверяет всю цепочку БЕЗ поднятия GUI (customtkinter недоступен в CI):
  1. PipelineOptions dataclass имеет 4 новых поля (sort_by_sni/bs_only/bs_allow_grey/bs_allow_fake).
  2. build_pipeline_args корректно превращает PipelineOptions в CLI-строки.
  3. subgen.pipeline.build_parser принимает все 4 новых флага (--sort-by-sni,
     --bs-only, --no-bs-allow-grey, --bs-allow-fake).
  4. subgen.settings.DEFAULT_TEST_OPTIONS включает 4 новых поля (для
     персистентности между запусками).
  5. Прямой вызов sni-фильтра на синтетике (как в pipeline.run()).

Файл БЕЗ GUI-зависимостей — все импорты lazy/stdlib-only.
"""
from __future__ import annotations

import sys
from dataclasses import fields as dataclass_fields
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


print("== 1. PipelineOptions dataclass fields ==")
from ui.runner import PipelineOptions  # noqa: E402

field_names = {f.name for f in dataclass_fields(PipelineOptions)}
check("sort_by_sni field", "sort_by_sni" in field_names)
check("bs_only field", "bs_only" in field_names)
check("bs_allow_grey field", "bs_allow_grey" in field_names)
check("bs_allow_fake field", "bs_allow_fake" in field_names)

# Проверяем дефолты.
opts = PipelineOptions()
check("sort_by_sni default=False", opts.sort_by_sni is False, f"got {opts.sort_by_sni}")
check("bs_only default=False", opts.bs_only is False, f"got {opts.bs_only}")
check("bs_allow_grey default=True", opts.bs_allow_grey is True, f"got {opts.bs_allow_grey}")
check("bs_allow_fake default=False", opts.bs_allow_fake is False, f"got {opts.bs_allow_fake}")


print()
print("== 2. build_pipeline_args: PipelineOptions → CLI ==")
from ui.runner import build_pipeline_args  # noqa: E402

# 2a) Все 4 флага включены.
opts_all = PipelineOptions(sort_by_sni=True, bs_only=True, bs_allow_grey=False, bs_allow_fake=True)
args_all = build_pipeline_args(opts_all, ["data/sources.txt"])
check("with all SNI: --sort-by-sni present", "--sort-by-sni" in args_all, str(args_all))
check("with all SNI: --bs-only present", "--bs-only" in args_all, str(args_all))
check("with bs_allow_grey=False: --no-bs-allow-grey present",
      "--no-bs-allow-grey" in args_all, str(args_all))
check("with bs_allow_fake=True: --bs-allow-fake present",
      "--bs-allow-fake" in args_all, str(args_all))

# 2b) Все SNI флаги выключены — никакой SNI-строки в args.
opts_none = PipelineOptions()
args_none = build_pipeline_args(opts_none, ["data/sources.txt"])
sni_args = [a for a in args_none if "sni" in a.lower() or a.startswith("--bs")]
check("with no SNI flags: no --sort-by-sni / --bs-* in args",
      "--sort-by-sni" not in args_none and "--bs-only" not in args_none
      and "--bs-allow-grey" not in args_none and "--no-bs-allow-grey" not in args_none
      and "--bs-allow-fake" not in args_none,
      str(sni_args))

# 2c) Только sort_by_sni (без bs_only) — фильтрации нет, только сортировка.
opts_sort_only = PipelineOptions(sort_by_sni=True)
args_sort_only = build_pipeline_args(opts_sort_only, ["data/sources.txt"])
check("--sort-by-sni alone: --sort-by-sni present", "--sort-by-sni" in args_sort_only)
check("--sort-by-sni alone: --bs-only NOT present (no filtering)",
      "--bs-only" not in args_sort_only, str(args_sort_only))

# 2d) bs_only=True, bs_allow_grey=True (default) — НЕ передаём --no-bs-allow-grey.
opts_bs_default_grey = PipelineOptions(bs_only=True, bs_allow_grey=True)
args_bs_default = build_pipeline_args(opts_bs_default_grey, [])
check("bs_only+allow_grey(default): --bs-only present", "--bs-only" in args_bs_default)
check("bs_only+allow_grey(default): NO --no-bs-allow-grey (it's default)",
      "--no-bs-allow-grey" not in args_bs_default, str(args_bs_default))


print()
print("== 3. argparse: pipeline.build_parser принимает новые флаги ==")
from subgen.pipeline import build_parser  # noqa: E402

parser = build_parser()

# 3a) Все флаги вместе.
args = parser.parse_args([
    "--sort-by-sni", "--bs-only", "--no-bs-allow-grey", "--bs-allow-fake",
    "--sources", "x.txt",
])
check("parse: --sort-by-sni", args.sort_by_sni is True)
check("parse: --bs-only", args.bs_only is True)
check("parse: --no-bs-allow-grey (False)", args.bs_allow_grey is False)
check("parse: --bs-allow-fake (True)", args.bs_allow_fake is True)

# 3b) Default (no new flags).
args = parser.parse_args(["--sources", "x.txt"])
check("parse default: sort_by_sni=False", args.sort_by_sni is False)
check("parse default: bs_only=False", args.bs_only is False)
check("parse default: bs_allow_grey=True", args.bs_allow_grey is True)
check("parse default: bs_allow_fake=False", args.bs_allow_fake is False)

# 3c) Только --bs-only — bs_allow_grey остаётся True (default).
args = parser.parse_args(["--bs-only", "--sources", "x.txt"])
check("parse --bs-only alone: bs_only=True", args.bs_only is True)
check("parse --bs-only alone: bs_allow_grey still True (default)",
      args.bs_allow_grey is True)
check("parse --bs-only alone: bs_allow_fake still False",
      args.bs_allow_fake is False)


print()
print("== 4. settings.DEFAULT_TEST_OPTIONS: поля для персистентности ==")
from subgen.settings import DEFAULT_TEST_OPTIONS  # noqa: E402

check("DEFAULT_TEST_OPTIONS has sort_by_sni",
      "sort_by_sni" in DEFAULT_TEST_OPTIONS)
check("DEFAULT_TEST_OPTIONS has bs_only",
      "bs_only" in DEFAULT_TEST_OPTIONS)
check("DEFAULT_TEST_OPTIONS has bs_allow_grey",
      "bs_allow_grey" in DEFAULT_TEST_OPTIONS)
check("DEFAULT_TEST_OPTIONS has bs_allow_fake",
      "bs_allow_fake" in DEFAULT_TEST_OPTIONS)
check("default sort_by_sni=False", DEFAULT_TEST_OPTIONS["sort_by_sni"] is False)
check("default bs_only=False", DEFAULT_TEST_OPTIONS["bs_only"] is False)
check("default bs_allow_grey=True", DEFAULT_TEST_OPTIONS["bs_allow_grey"] is True)
check("default bs_allow_fake=False", DEFAULT_TEST_OPTIONS["bs_allow_fake"] is False)


print()
print("== 5. SNI-категоризация: pipeline-style фильтр + сортировка ==")
# Симулируем финальный этап pipeline.run: после stress-test на руках список
# XrayProbeResult. Применяем SNI-фильтр/сортировку как в pipeline.py.
from checkers.sni_category import (  # noqa: E402
    SNI_CATEGORY_PRIORITY,
    category_summary,
    passes_filter as _bs_passes,
    sni_category as _sni_cat,
)
from runtime.types import XrayNode, XrayProbeResult  # noqa: E402


def _mk(protocol: str = "vless", host: str = "1.2.3.4", port: int = 443,
        query: dict[str, str] | None = None, name: str = "") -> XrayProbeResult:
    node = XrayNode(
        protocol=protocol,
        raw_url=f"{protocol}://uuid@{host}:{port}",
        name=name or f"{protocol}://{host}:{port}",
        host=host, port=port, credential="00000000-0000-0000-0000-000000000000",
        query=query or {},
    )
    return XrayProbeResult(node, True, "tested", 50.0, 1000, 1, "xray")


# 4 узла разных SNI-категорий.
working = [
    _mk(query={"sni": "instagram.com"}, name="cs_node"),        # black
    _mk(query={"sni": "realhost.com"}, name="grey_node"),        # grey
    _mk(query={"sni": "abc12345"}, name="fake_node"),            # fake
    _mk(query={"sni": "www.sberbank.ru"}, name="bs_node"),       # white
]
summary = category_summary([w.node for w in working])
check("synthetic breakdown: 1 bs, 1 grey, 1 fake, 1 cs",
      summary.get("white", 0) == 1 and summary.get("grey", 0) == 1
      and summary.get("fake", 0) == 1 and summary.get("black", 0) == 1,
      str(summary))

# 5a) bs_only=True, allow_grey=True, allow_fake=False — оставить bs + grey.
filtered = [w for w in working if _bs_passes(w.node, allow_grey=True, allow_fake=False)]
check("bs_only+allow_grey: 2 узла survive (bs + grey)",
      len(filtered) == 2 and "bs_node" in [w.node.name for w in filtered]
      and "grey_node" in [w.node.name for w in filtered], str([w.node.name for w in filtered]))

# 5b) bs_only=True, allow_grey=False, allow_fake=False — строгий, только bs.
filtered = [w for w in working if _bs_passes(w.node, allow_grey=False, allow_fake=False)]
check("bs_only strict: 1 узел survive (only bs)",
      len(filtered) == 1 and filtered[0].node.name == "bs_node",
      str([w.node.name for w in filtered]))

# 5c) sort_by_sni=True — БС идёт первым.
sorted_w = sorted(working,
                  key=lambda w: SNI_CATEGORY_PRIORITY.get(_sni_cat(w.node), 99))
cats = [_sni_cat(w.node) for w in sorted_w]
check("sort_by_sni: first is white (bs_node)",
      cats[0] == "white" and sorted_w[0].node.name == "bs_node", str(cats))
check("sort_by_sni: last is black (cs_node)",
      cats[-1] == "black" and sorted_w[-1].node.name == "cs_node", str(cats))
check("sort_by_sni: order is [white, grey, fake, black]",
      cats == ["white", "grey", "fake", "black"], str(cats))


print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
