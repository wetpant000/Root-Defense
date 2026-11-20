#!/usr/bin/env bash
# One-time setup for Root-Defense (run on both System A and System B).
#   - Python 3.10+ virtual environment with the backend dependencies
#   - Node.js packages for the chain tooling (Hardhat local chain, solc, quais SDK) - System B only needs these,
#     but installing them on A is harmless
#   - compiles the RootRegistry contract
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say() { printf "\033[1;36m==>\033[0m %s\n" "$*"; }

command -v python3 >/dev/null || { echo "python3 is required (3.10+)"; exit 1; }
python3 - <<'EOF' || { echo "Python 3.10+ is required"; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
EOF

if [[ ! -x .venv/bin/python ]]; then
  say "Creating Python virtual environment (.venv)"
  python3 -m venv .venv
fi
say "Installing Python dependencies"
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

if command -v npm >/dev/null; then
  say "Installing chain tooling (Hardhat, solc, quais)"
  (cd chain && npm install --no-audit --no-fund --loglevel=error)
  say "Compiling RootRegistry contract"
  (cd chain && node compile.js)
else
  echo "npm not found: skipping chain tooling. System B (witness) needs Node.js 18+; System A (agent) does not."
fi

chmod +x rd
say "Done. Next steps:"
cat <<'EOF'
  System B (witness):  ./rd init-witness   then   ./rd up
  System A (agent):    ./rd init-agent --witness http://<B-ip>:8800 --token <token>   then   ./rd up-agent
EOF
