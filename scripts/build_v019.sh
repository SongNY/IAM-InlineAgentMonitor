#!/usr/bin/env bash
# Build v0.19 dataset: v0.18 sources + new v19 attack scenarios.
#
# Adds (vs v0.18):
#   - memory_poisoning v2 (weak) + v3 (strong) families
#   - tool_description_injection
#   - mcp_rug_pull
#   - prompt_extraction_multi_turn
#   - iif3_destructive (rewrite of failing destroy-* family)
#   - iif3_exfil_extended (kubeconfig/.ssh/.npmrc/.env via iif3 framing)
#   - excessive_agency
#   - log_poisoning / corrupted tool feedback
#   - jwt_forgery (confused_deputy variant)
#   - cross_tenant_leak
#   - dependency_confusion
set -eu
cd "$(dirname "$0")/.."

PY="${PY:-python3}"   # override with: PY=/path/to/python ./scripts/build_v019.sh
VER=19
OUT="data/v0.${VER}"
LOG="logs-v19/build.log"
mkdir -p "$OUT" logs-v19

echo "=== build v0.${VER} start $(date) ===" | tee -a "$LOG"

# v0.18 source dirs (whatever feeds the existing dataset) + new v19 dirs.
INCLUDES=(
  runs-v1 runs-permissive runs-react runs-react-ext runs-langgraph
  runs-v02-flash runs-v02-pro runs-v02-iif3 runs-v02-auto
  runs-v02-sandbox runs-v02-claude
  runs-v03-newcats runs-v03-newcats-auto
  runs-v04-temp05
  runs-mrt runs-atbench
  # NOTE: runs-history (1695 pure-safe Claude history traces) is excluded
  # from v0.19 to keep anomaly ratio near 40%. Add it back if you want a
  # benign-heavy distribution.
  runs-overnight-t06 runs-mrt-overnight
  runs-sonnet-attacks runs-sonnet-benign
  runs-opus-iif runs-opus-deputy runs-opus-persist runs-opus-outman runs-opus-cve runs-opus-sandbox
  runs-wave3-t07 runs-wave3-t08
  # v0.19 additions
  runs-v19-deepseek-t05 runs-v19-deepseek-t07
  runs-v19-mempoison3-t06 runs-v19-mempoison3-t07b
  runs-v19-newfams-t06
  runs-v19-promptextc-t08
  runs-v19-iif3d2-t06 runs-v19-iif3x2-t06
  runs-v19-a3s-t05
  runs-v19-rerun-t07
  runs-v19-a3s-memory-t06
)

ARGS=()
for d in "${INCLUDES[@]}"; do
  if [ -d "$d" ]; then
    ARGS+=( "$d" )
  fi
done

echo "INCLUDE dirs:" | tee -a "$LOG"
for d in "${ARGS[@]}"; do echo "  $d" | tee -a "$LOG"; done

$PY scripts/build_dataset.py \
  --include "${ARGS[@]}" \
  --out "$OUT/" \
  --val 0.10 --test 0.10 --seed 42 2>&1 | tee -a "$LOG"

echo "=== tokenize ===" | tee -a "$LOG"
for split in train val test; do
  echo "tokenize $split..." | tee -a "$LOG"
  $PY scripts/tokenize_dataset.py \
    --in "$OUT/$split.jsonl" \
    --out "$OUT/$split.tokenized.jsonl" \
    --tokenizer Qwen/Qwen3.5-2B \
    --max-length 4096 2>&1 | tee -a "$LOG"
done

echo "=== build v0.${VER} DONE $(date) ===" | tee -a "$LOG"
wc -l "$OUT"/*.jsonl | tee -a "$LOG"
