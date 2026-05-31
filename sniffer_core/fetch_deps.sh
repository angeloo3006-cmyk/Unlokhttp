#!/usr/bin/env bash
# ES: Descarga la cabecera unica nlohmann/json en sniffer_core/. / EN: Downloads the nlohmann/json single header into sniffer_core/.
set -euo pipefail

DEST="$(dirname "$0")/json.hpp"
VERSION="3.12.0"
URL="https://github.com/nlohmann/json/releases/download/v${VERSION}/json.hpp"

if [ -f "$DEST" ]; then
  echo "json.hpp already present; skipping download."
  exit 0
fi

echo "Downloading nlohmann/json v${VERSION} ..."
if command -v curl &>/dev/null; then
  curl -fsSL "$URL" -o "$DEST"
elif command -v wget &>/dev/null; then
  wget -q "$URL" -O "$DEST"
else
  echo "ERROR: curl or wget not found. Download manually from $URL"
  exit 1
fi

echo "Done: $DEST"
