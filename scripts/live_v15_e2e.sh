#!/usr/bin/env bash
# Живой интеграционный тест v15: полный прогон конвейера на BlancVPN + мёртвая ссылка.
# Проверяем: trace.log с воронкой, report.json секция trace, upload/tg_media != null.
set -e
cd /home/z/my-project/sub_generator

TMP=$(mktemp -d)
mkdir -p "$TMP"
cat > "$TMP/sources.txt" <<'EOF'
https://0dceb06f.withblancvpn.online/s/a91b6cba9cec463cb20cbb8d17e71b35#BlancVPN
https://example.invalid/dead-sub.txt
EOF

export PYTHONPATH="$PWD/python:$PWD"
timeout 900 python3 generate.py --cli \
  --sources "https://0dceb06f.withblancvpn.online/s/a91b6cba9cec463cb20cbb8d17e71b35" "https://example.invalid/dead-sub.txt" \
  --workers 8 \
  --timeout 10 \
  --limit 12 \
  --out "$TMP/subs.txt" \
  --working "$TMP/working.txt" \
  --report "$TMP/report.json" \
  --geo-cache "$TMP/geo.json" \
  --no-stress 2>&1 | grep -E "^\[(trace|sub)\]|filter|sources:" | head -40

echo "=== trace.log ==="
cat data/trace.log 2>/dev/null | head -50
echo
echo "=== report.json: trace + nodes metrics ==="
python3 - "$TMP/report.json" <<'PYEOF'
import json, sys
r = json.load(open(sys.argv[1], encoding='utf-8'))
tr = r.get('trace', {})
print('trace.enabled:', tr.get('enabled'))
print('checkpoints:', tr.get('checkpoints_done'))
for s in tr.get('sources', []):
    print(' SRC', s['source'][:60], '->', {k: v for k, v in s['funnel'].items() if v})
    print('     lost_at:', s['lost_at'])
nodes = r.get('nodes', [])
print('экспортировано узлов:', len(nodes))
for n in nodes[:6]:
    print('  ', n['name'], 'dl=', n.get('download_kbps'), 'ul=', n.get('upload_kbps'), 'tg=', n.get('tg_media_kbps'))
non_null_up = sum(1 for n in nodes if n.get('upload_kbps') is not None)
non_null_tg = sum(1 for n in nodes if n.get('tg_media_kbps') is not None)
print(f'upload_kbps не null: {non_null_up}/{len(nodes)}; tg_media_kbps не null: {non_null_tg}/{len(nodes)}')
sr = r.get('sources_report', {})
print('sources_report: contributed=', sr.get('contributed'), 'dead=', sr.get('dead'))
for e in sr.get('nodes', [])[:4]:
    print('  ', e['source'][:60], 'disc=', e.get('discovered'), 'exp=', e.get('exported'), 'empty=', e.get('empty'), 'funnel=', {k: v for k, v in (e.get('funnel') or {}).items() if v})
PYEOF
