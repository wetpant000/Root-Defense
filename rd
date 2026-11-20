#!/usr/bin/env bash
# Root-Defense launcher: runs the CLI inside the project's virtual environment.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -x "$DIR/.venv/bin/python" ]]; then
  if [[ "${1:-}" == "setup" ]]; then exec bash "$DIR/scripts/setup.sh"; fi
  echo "Python environment missing. Run: ./rd setup" >&2
  exit 1
fi
cd "$DIR"
exec "$DIR/.venv/bin/python" -m rootdefense "$@"
