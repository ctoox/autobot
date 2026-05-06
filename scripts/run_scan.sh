#!/usr/bin/env bash
# Quick scan and refactor script for daily ops maintenance

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

TARGET_DIR="${1:-.}"
REPO_URL="${2:-}"
DRY_RUN="${3:-false}"

echo "=== OpenClaw Ops Agent ==="
echo "Target: $TARGET_DIR"
echo "Dry run: $DRY_RUN"
echo ""

cd "$PROJECT_DIR"

echo "[1/4] Scanning scripts..."
python -m src scan --target "$TARGET_DIR" --output ./scan-report.json

echo "[2/4] Checking security baseline..."
python -m src security --target "$TARGET_DIR"

echo "[3/4] Validating network specs..."
python -m src validate --target "$TARGET_DIR"

if [ "$DRY_RUN" = "true" ]; then
    echo "[4/4] Dry run - showing refactor plan..."
    python -m src refactor --target "$TARGET_DIR" --dry-run
else
    if [ -z "$REPO_URL" ]; then
        echo "[4/4] Skipping PR generation (no repo URL provided)"
    else
        echo "[4/4] Generating PR for $REPO_URL..."
        python -m src refactor --target "$TARGET_DIR" --repo "$REPO_URL"
    fi
fi

echo ""
echo "Done."
