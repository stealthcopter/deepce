#!/bin/sh
# Test: Kubernetes SA token detection with mocked environment
# Simulates running inside a K8s pod by setting env vars and creating fake SA files

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEEPCE="$SCRIPT_DIR/../deepce.sh"

echo "=== deepce K8s SA Token Detection Test ==="

# Create a temporary mock SA directory
TMPDIR=$(mktemp -d)
MOCK_SA="$TMPDIR/serviceaccount"
mkdir -p "$MOCK_SA"

# Create a fake JWT token (header.payload.sig — payload is base64 of JSON with exp)
PAYLOAD=$(printf '{"sub":"system:serviceaccount:default:test-sa","namespace":"default","exp":9999999999}' | base64 | tr -d '=\n' | tr '+/' '-_')
FAKE_TOKEN="eyJhbGciOiJSUzI1NiJ9.${PAYLOAD}.fakesig"
printf '%s' "$FAKE_TOKEN" > "$MOCK_SA/token"
printf 'default' > "$MOCK_SA/namespace"
printf 'fake-ca-cert' > "$MOCK_SA/ca.crt"

echo "[*] Mock SA token created at $MOCK_SA"
echo "[*] Running deepce with --token flag (no-enum mode to skip container detection)..."

# Run with forced K8s mode, custom token path, skip exploit — just enumerate SA
export KUBERNETES_SERVICE_HOST="10.96.0.1"
export KUBERNETES_SERVICE_PORT="443"

sh "$DEEPCE" -k --token "$MOCK_SA/token" -ne -nc -q 2>&1 | head -40

echo ""
echo "[*] Checking runc version exploit detection..."
sh "$DEEPCE" -nc -q -ne 2>&1 | grep -i "runc\|CVE-2024\|CVE-2025" | head -10

# Cleanup
rm -rf "$TMPDIR"
echo "[*] Test complete"
