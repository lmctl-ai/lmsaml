#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Building lmsaml ==="
CGO_ENABLED=0 go build -trimpath -o lmsaml ./cmd/lmsaml

echo "=== Running Go unit tests ==="
go test ./cmd/lmsaml/... ./samlidp/...

echo "=== Running SAML 2.0, REST, lmconn, lmcurl & lmcode integration tests ==="
chmod +x ./tests/integration-test.sh
./tests/integration-test.sh

echo "=== All lmsaml tests passed! ==="
