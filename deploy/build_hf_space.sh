#!/usr/bin/env bash
# Assemble a clean Hugging Face Space (Docker SDK) for the PUBLIC dashboard demo.
# Only the dashboard code, the synthetic demo log and the redacted result files are included:
# no guard/gate code, no .env, no tokens, no raw benchmark progress.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/hf-space}"
rm -rf "$OUT" && mkdir -p "$OUT/benchmark/results"
cp -R "$ROOT/core" "$ROOT/dashboard" "$ROOT/.streamlit" "$ROOT/requirements-dashboard.txt" "$OUT/"
for f in results.json external.json ghsa.json real_repos.json; do
  cp "$ROOT/benchmark/results/$f" "$OUT/benchmark/results/"
done
find "$OUT" -name "__pycache__" -prune -exec rm -rf {} +
sed 's/^ARG PUBLIC=0/ARG PUBLIC=1/' "$ROOT/Dockerfile" > "$OUT/Dockerfile"
cp "$ROOT/deploy/hf_space_README.md" "$OUT/README.md"
echo "Space folder ready: $OUT"
