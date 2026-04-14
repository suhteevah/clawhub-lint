#!/usr/bin/env bash
# clawhub-lint installer
# Usage:
#   curl -sSL https://raw.githubusercontent.com/suhteevah/clawhub-lint/main/install.sh | bash
#   ./install.sh
#   ./install.sh --uninstall

set -euo pipefail

REPO_URL="https://github.com/suhteevah/clawhub-lint.git"
RAW_URL="https://raw.githubusercontent.com/suhteevah/clawhub-lint/main/install.sh"
INSTALL_DIR="$HOME/.clawhub-lint"
BIN_NAME="clawhub-lint"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[x]${NC} $*" >&2; }
fatal() { err "$@"; exit 1; }

# ============================================================================
# Detect OS and set bin directory
# ============================================================================

detect_platform() {
  case "$(uname -s)" in
    Linux*)   PLATFORM="linux" ;;
    Darwin*)  PLATFORM="macos" ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
    *)        PLATFORM="unknown" ;;
  esac

  # Determine where to put the symlink/wrapper
  if [[ "$PLATFORM" == "windows" ]]; then
    BIN_DIR="$HOME/bin"
  else
    if [[ -w /usr/local/bin ]]; then
      BIN_DIR="/usr/local/bin"
    else
      BIN_DIR="$HOME/.local/bin"
    fi
  fi
}

# ============================================================================
# Uninstall
# ============================================================================

uninstall() {
  info "Uninstalling clawhub-lint..."

  detect_platform

  # Remove bin link/wrapper
  for candidate in /usr/local/bin/$BIN_NAME "$HOME/.local/bin/$BIN_NAME" "$HOME/bin/$BIN_NAME"; do
    if [[ -e "$candidate" || -L "$candidate" ]]; then
      rm -f "$candidate"
      info "Removed $candidate"
    fi
  done

  # Remove install directory
  if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    info "Removed $INSTALL_DIR"
  fi

  info "clawhub-lint uninstalled."
  exit 0
}

# ============================================================================
# Install
# ============================================================================

install() {
  detect_platform
  info "Platform: $PLATFORM"
  info "Install dir: $INSTALL_DIR"
  info "Bin dir: $BIN_DIR"

  # Get the source: either we're running from inside a clone, or we need to clone
  local SOURCE_DIR=""
  local SCRIPT_REAL
  SCRIPT_REAL="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"

  if [[ -f "$SCRIPT_REAL/clawhub-lint.sh" && -d "$SCRIPT_REAL/tools" ]]; then
    SOURCE_DIR="$SCRIPT_REAL"
    info "Installing from local repo: $SOURCE_DIR"
  else
    # Running via curl pipe — clone to temp
    local TMPDIR
    TMPDIR="$(mktemp -d)"
    trap "rm -rf '$TMPDIR'" EXIT
    info "Cloning from $REPO_URL..."
    git clone --depth 1 "$REPO_URL" "$TMPDIR/clawhub-lint" || fatal "git clone failed"
    SOURCE_DIR="$TMPDIR/clawhub-lint"
  fi

  # Remove old install if present
  if [[ -d "$INSTALL_DIR" ]]; then
    warn "Removing previous install at $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
  fi

  # Copy repo to install dir
  cp -r "$SOURCE_DIR" "$INSTALL_DIR"
  info "Copied to $INSTALL_DIR"

  # Make everything executable
  chmod +x "$INSTALL_DIR/clawhub-lint.sh"
  find "$INSTALL_DIR/tools" -name '*.sh' -exec chmod +x {} +
  find "$INSTALL_DIR/lib" -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
  info "Set executable permissions"

  # Create bin directory if needed
  mkdir -p "$BIN_DIR"

  # Create symlink or wrapper
  local LINK_PATH="$BIN_DIR/$BIN_NAME"
  rm -f "$LINK_PATH"

  if [[ "$PLATFORM" == "windows" ]]; then
    # On MSYS/Git Bash, symlinks can be unreliable — use a wrapper script
    cat > "$LINK_PATH" <<'WRAPPER'
#!/usr/bin/env bash
exec "$HOME/.clawhub-lint/clawhub-lint.sh" "$@"
WRAPPER
    chmod +x "$LINK_PATH"
    info "Created wrapper at $LINK_PATH"
  else
    ln -sf "$INSTALL_DIR/clawhub-lint.sh" "$LINK_PATH"
    info "Symlinked $LINK_PATH -> $INSTALL_DIR/clawhub-lint.sh"
  fi

  # Ensure bin dir is in PATH (advise user if not)
  if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    warn "$BIN_DIR is not in your PATH."
    echo ""
    echo "  Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    echo ""
    echo "    export PATH=\"$BIN_DIR:\$PATH\""
    echo ""
  fi

  # Verify installation
  echo ""
  info "Verifying installation..."
  if "$LINK_PATH" list >/dev/null 2>&1; then
    "$LINK_PATH" list
    echo ""
    "$LINK_PATH" count
    echo ""
    info "clawhub-lint installed successfully!"
  else
    # Fallback: run directly
    "$INSTALL_DIR/clawhub-lint.sh" list
    echo ""
    "$INSTALL_DIR/clawhub-lint.sh" count
    echo ""
    info "clawhub-lint installed (run via $INSTALL_DIR/clawhub-lint.sh)"
  fi

  # Print shareable install command
  echo ""
  echo -e "${BOLD}Share this one-liner:${NC}"
  echo ""
  echo "  curl -sSL $RAW_URL | bash"
  echo ""
}

# ============================================================================
# Main
# ============================================================================

case "${1:-}" in
  --uninstall|-u|uninstall)
    uninstall
    ;;
  --help|-h|help)
    echo "Usage: install.sh [--uninstall]"
    echo ""
    echo "Installs clawhub-lint to ~/.clawhub-lint/ and creates a PATH-accessible command."
    echo ""
    echo "  --uninstall   Remove clawhub-lint"
    echo "  --help        Show this help"
    echo ""
    echo "One-liner install:"
    echo "  curl -sSL $RAW_URL | bash"
    ;;
  *)
    install
    ;;
esac
