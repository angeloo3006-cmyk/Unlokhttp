#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${SCRIPT_DIR}/fetch_deps.sh"

cmake -S "${SCRIPT_DIR}" -B "${SCRIPT_DIR}/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCOPY_TO_TAURI=ON
cmake --build "${SCRIPT_DIR}/build" --config Release
