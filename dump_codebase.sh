#!/usr/bin/env bash

set -euo pipefail

# ---------------------------
# Usage check
# ---------------------------
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <source_folder> <output_file>"
  exit 1
fi

SRC_DIR="$(cd "$1" && pwd)"
OUT_FILE="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

# ---------------------------
# Safety checks
# ---------------------------
if [ ! -d "$SRC_DIR" ]; then
  echo "Error: Source folder does not exist: $SRC_DIR"
  exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"

# ---------------------------
# Clean output file
# ---------------------------
: > "$OUT_FILE"

# ---------------------------
# Dump files
# ---------------------------
find "$SRC_DIR" -type f \
  ! -path "*/node_modules/*" \
  ! -path "*/.git/*" \
  ! -path "*/dist/*" \
  ! -path "*/build/*" \
  ! -path "*/target/*" \
  ! -path "*/.idea/*" \
  ! -path "*/.vscode/*" \
  \( \
    -name "*.java" \
    -o -name "*.ts" \
    -o -name "*.js" \
    -o -name "*.properties" \
    -o -name "*.yml" \
    -o -name "*.yaml" \
    -o -name "*.sql" \
  \) \
| sort \
| while read -r file; do
    {
      echo ""
      echo "========================================"
      echo "FILE: ${file#$SRC_DIR/}"
      echo "========================================"

      # Redact common secrets but keep keys
      sed -E '
        s/(password|passwd|secret|token|api[_-]?key)[[:space:]]*=[[:space:]]*.*/\1=****REDACTED****/I;
        s/(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY).*/\1=****REDACTED****/I
      ' "$file"
    } >> "$OUT_FILE"
done

echo "✔ Codebase dumped to: $OUT_FILE"
