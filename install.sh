set -euo pipefail

PREFIX="${1:-/usr/local}"
BINARY_NAME="kitinspect"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="1.0.0"
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

log()    { printf "${CYAN}[kitinspect]${RESET} %s\n" "$*"; }
ok()     { printf "${GREEN}  ✔  %s${RESET}\n" "$*"; }
warn()   { printf "${YELLOW}  ⚠  %s${RESET}\n" "$*"; }
fail()   { printf "${RED}  ✖  %s${RESET}\n" "$*"; exit 1; }

echo ""
printf "${CYAN}"
echo "  ╔════════════════════════════════════════════╗"
echo "  ║     KitInspect v${VERSION} — Installer         ║"
echo "  ║  Professional APK Security Analysis Tool  ║"
echo "  ╚════════════════════════════════════════════╝"
printf "${RESET}\n"
log "Checking prerequisites..."

if ! command -v go &>/dev/null; then
    fail "Go is not installed. Install from: https://go.dev/dl/"
fi

GO_VERSION=$(go version | awk '{print $3}' | tr -d 'go')
REQUIRED="1.21"
if [[ "$(printf '%s\n' "$REQUIRED" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED" ]]; then
    fail "Go $REQUIRED+ required, found $GO_VERSION"
fi
ok "Go $GO_VERSION found"
PYTHON_BIN=""
for py in python3 python; do
    if command -v $py &>/dev/null; then
        PY_VER=$($py --version 2>&1 | awk '{print $2}')
        PYTHON_BIN=$py
        ok "Python $PY_VER found ($py)"
        break
    fi
done
if [[ -z "$PYTHON_BIN" ]]; then
    warn "Python not found. Python analysis engine will be unavailable."
fi
log "Building KitInspect..."
cd "$REPO_ROOT"

GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS="-X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -w -s"

go mod download
go build -ldflags "${LDFLAGS}" -trimpath -o "${BINARY_NAME}" ./cmd/kitinspect/
ok "Binary built: ${BINARY_NAME}"
log "Installing to ${PREFIX}/bin/${BINARY_NAME}..."
mkdir -p "${PREFIX}/bin"
install -m 755 "${BINARY_NAME}" "${PREFIX}/bin/${BINARY_NAME}"
ok "Installed: ${PREFIX}/bin/${BINARY_NAME}"
PYTHON_DIR="${PREFIX}/lib/kitinspect/python"
log "Installing Python engine to ${PYTHON_DIR}..."
mkdir -p "${PYTHON_DIR}"
cp -r python/ "${PYTHON_DIR}/"
ok "Python engine installed"
echo ""
log "Verifying installation..."
if "${PREFIX}/bin/${BINARY_NAME}" version &>/dev/null; then
    ok "KitInspect is working"
else
    warn "Binary installed but failed to run. Check PATH or permissions."
fi
echo ""
printf "${GREEN}"
echo "  ╔════════════════════════════════════════════╗"
echo "  ║         Installation Complete! ✔           ║"
echo "  ╚════════════════════════════════════════════╝"
printf "${RESET}"
echo ""
echo "  Quick Start:"
echo ""
echo "    kitinspect scan app.apk         # Full analysis"
echo "    kitinspect permissions app.apk  # Permission audit"
echo "    kitinspect cert app.apk         # Certificate check"
echo "    kitinspect strings app.apk      # String & IOC extraction"
echo "    kitinspect report app.apk       # Generate report"
echo "    kitinspect tui                  # Interactive TUI"
echo ""
echo "  Documentation: https://github.com/kitinspect/kitinspect"
echo ""
