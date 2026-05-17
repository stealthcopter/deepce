#!/bin/sh
# Test: Cloud metadata endpoint detection
# Checks that deepce correctly probes AWS/GCP/Azure metadata endpoints
# Note: will only produce hits if running in a real cloud environment

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEEPCE="$SCRIPT_DIR/../deepce.sh"

echo "=== deepce Cloud Metadata Detection Test ==="
echo "[*] This test will attempt to reach real metadata endpoints."
echo "[*] Expected: No in CI/local; hits only in AWS/GCP/Azure."
echo ""

# Run metadata check only (skip full enumeration)
sh "$DEEPCE" -nc -ne -km 2>&1

echo ""
echo "[*] Test complete"
