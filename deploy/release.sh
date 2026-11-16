#!/usr/bin/env bash
# Build the agent for every platform and publish it to https://httpowl.net/dl/,
# together with the installers. Usage: deploy/release.sh [production|staging]
# Agents already installed keep running; re-running the installer updates them.
set -euo pipefail
cd "$(dirname "$0")/.."
HOST=${HOST:-root@213.130.144.132}
# Target: production (default) or staging, e.g. `deploy/deploy.sh staging`.
TARGET=${1:-production}
case "$TARGET" in
  production) DIR=/var/www/httpowl;         SERVICE=httpowl-api;         PORT=8090; URL=https://httpowl.net ;;
  staging)    DIR=/var/www/httpowl-staging; SERVICE=httpowl-staging-api; PORT=8091; URL=https://staging.httpowl.net ;;
  *) echo "usage: $0 [production|staging]"; exit 1 ;;
esac
DL=$DIR/dl
VERSION=$(git describe --always --dirty)
OUT=dist
rm -rf "$OUT"; mkdir -p "$OUT"
go vet ./... && go test ./...
for t in linux/amd64 linux/arm64 windows/amd64; do
  os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=.exe
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/httpowl-agent-$os-$arch$ext" ./cmd/httpowl-agent
done
(cd "$OUT" && shasum -a 256 httpowl-agent-* > SHA256SUMS)
# The installers default to the server they are downloaded from.
sed "s#^SERVER=\"https://httpowl.net\"#SERVER=\"$URL\"#" deploy/install.sh > "$OUT/install.sh"
sed "s#else { \"https://httpowl.net\" }#else { \"$URL\" }#" deploy/install.ps1 > "$OUT/install.ps1"
COPYFILE_DISABLE=1 tar --no-xattrs -czf - -C "$OUT" . | ssh "$HOST" "set -e; T=\$(mktemp -d); tar xzf - -C \$T; install -o root -g root -m 0644 \$T/* $DL/; rm -rf \$T"
curl -fsS $URL/dl/SHA256SUMS
echo "released agent $VERSION to $TARGET"
