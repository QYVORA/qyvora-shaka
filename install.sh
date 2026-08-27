#!/usr/bin/env bash
#
# SHAKA install helper.
#
# Builds shaka from source and installs it with an icon and desktop entry.
#   ./install.sh            user install (default, no root required)
#   ./install.sh --system   system-wide install under /usr/local (may need sudo)
#   ./install.sh --help     usage
#
# Alternatively use the Makefile targets directly:
#   make install        # system-wide (/usr/local)
#   make install-user   # per-user (~/.local)
set -euo pipefail

FAIL='\033[31m'
GREEN='\033[32m'
CYAN='\033[36m'
NC='\033[0m'

fail() { echo -e "${FAIL}[ERROR]${NC} $*" >&2; exit 1; }
log()  { echo -e "${CYAN}[SHAKA]${NC} $*"; }
pass() { echo -e "${GREEN}  ok${NC}  $*"; }

MODE="user"

usage() {
  echo "Usage: $0 [--system] [--help]"
  echo "  --system   install system-wide under /usr/local"
  echo "  (default)  install per-user under ~/.local"
  echo ""
  echo "Installs: shaka binary, share icon, and desktop entry."
}

while [ $# -gt 0 ]; do
  case "$1" in
    --system) MODE="system"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "Unknown option: $1 (try --help)" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

log "Building shaka from source..."
make build || fail "build failed"

if [ "$MODE" = "system" ]; then
  log "Installing shaka system-wide (/usr/local)..."
  make install
else
  log "Installing shaka for user ($HOME/.local)..."
  make install-user
fi

pass "shaka installed. Run 'shaka version' to verify."
echo ""
echo "Next steps:"
echo "  shaka                    start the interactive console"
echo "  shaka assess --sim       run the full pipeline against the offline demo"
echo "  shaka assess -y --endpoint dc01:389   assess a live authorized directory"
