#!/usr/bin/env bash
#
# SHAKA — zero-config installer
#
# Automatically detects your operating system, CPU architecture, and shell,
# then installs the correct prebuilt binary with nothing for you to pick.
#  1. Detects OS (Linux / macOS / Windows-GitBash) and architecture (amd64/arm64)
#  2. Downloads the matching prebuilt binary from GitHub Releases and verifies
#     its SHA-256 against the published checksums.txt (supply-chain protection)
#  3. Falls back to building from source (needs Go) if the download fails
#  4. Installs to ~/.local/bin (no sudo required) and adds it to your shell
#     config automatically (bash / zsh / fish)
#  5. Verifies the install by printing the version
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-shaka/master/install.sh | bash
#   bash install.sh
#
# QYVORA OffSec

set -euo pipefail

# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
DIM='\033[90m'
NC='\033[0m'

REPO="QYVORA/qyvora-shaka"
BASE_URL="https://github.com/${REPO}/releases/latest/download"
DEFAULT_BIN_DIR="${HOME}/.local/bin"

log()  { echo -e "${DIM}[shaka]${NC} $*"; }
ok()   { echo -e "  ${GREEN}[OK]${NC} $*"; }
info() { echo -e "  ${CYAN}[..]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
die()  { echo -e "  ${RED}[!]${NC} $*" >&2; exit 1; }

banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}                       =+:"
    echo -e "${CYAN}                    -%@=*+:"
    echo -e "${CYAN}                   +@@#:**%="
    echo -e "${CYAN}                   .=*% +==."
    echo -e "${CYAN}    .==============-    +*+-+*+"
    echo -e "${CYAN}   .@@@@@@@@@@@@@@@@#*-     =%%%%%%%%%%%%%%%%%*"
    echo -e "${CYAN}  :@#%*++++++++++++**=.   :%#@#++++++++++++=:"
    echo -e "${CYAN}  :@=:@@#+============---==========-%@#@:"
    echo -e "${CYAN}  :#--@%          .-=+=-.          *##."
    echo -e "${CYAN}  .+=*@%          %#####%          *@#"
    echo -e "${CYAN}   #@##%           .==*+-.         #@%"
    echo -e "${CYAN}    .%@@*      :+:.:+: :+:.:+:   .%@%."
    echo -e "${CYAN}      .+%@@%=--.          .-----+@#+."
    echo -e "${CYAN}          .=%@@%:*%=.%@%*+.+%*:%@@%=."
    echo -e "${NC}"
    echo -e "  ${WHITE}SHAKA — Zero-Config Installer${NC}"
    echo -e "  ${CYAN}QYVORA OffSec — Tamale, Ghana${NC}"
    echo -e "  ${DIM}----------------------------------------${NC}"
    echo -e ""
}

# ---------------------------------------------------------------------------
# Detection: OS, architecture, shell
# ---------------------------------------------------------------------------
detect_os() {
    case "$(uname -s)" in
        Linux)                     echo "linux" ;;
        Darwin)                    echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*)      echo "windows" ;;
        *) die "Unsupported operating system: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)        echo "amd64" ;;
        aarch64|arm64)       echo "arm64" ;;
        i386|i686)           die "32-bit binaries are not published; build from source instead" ;;
        *) die "Unsupported architecture: $(uname -m)" ;;
    esac
}

detect_shell_rc() {
    case "${SHELL:-}" in
        *zsh)   echo "${ZDOTDIR:-$HOME}/.zshrc" ;;
        *fish)  echo "$HOME/.config/fish/config.fish" ;;
        *)      echo "$HOME/.bashrc" ;;
    esac
}

# ---------------------------------------------------------------------------
# Install from a checksum-verified prebuilt release binary
# ---------------------------------------------------------------------------
install_release() {
    local os="$1" arch="$2"
    local name="shaka-${os}-${arch}"
    [ "$os" = "windows" ] && name="${name}.exe"

    local local_bin="${WORK_DIR}/${name}"
    info "Detected ${os}/${arch} — downloading prebuilt ${name}..."
    if ! curl -fsSL --connect-timeout 10 "${BASE_URL}/${name}" -o "$local_bin"; then
        warn "Prebuilt binary download failed (offline or no release yet)."
        return 1
    fi

    # SHA-256 verification against the published checksums.txt
    local hashtool=""
    if command -v sha256sum >/dev/null 2>&1; then
        hashtool="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        hashtool="shasum -a 256"
    fi

    if [ -n "$hashtool" ]; then
        if curl -fsSL --connect-timeout 10 "${BASE_URL}/checksums.txt" -o "${WORK_DIR}/checksums.txt"; then
            local want got
            want=$(awk -v n="$name" '$2 == n { print $1 }' "${WORK_DIR}/checksums.txt")
            got=$($hashtool "$local_bin" | awk '{ print $1 }')
            if [ -z "$want" ]; then
                warn "No checksum entry found for ${name}; continuing without verification."
            elif [ "$want" = "$got" ]; then
                ok "SHA-256 verified for ${name} (${got})"
            else
                die "Checksum mismatch for ${name}! The downloaded binary may have been tampered with. Aborting."
            fi
        else
            warn "Could not fetch checksums.txt; continuing without verification."
        fi
    else
        warn "No sha256 tool found; skipping checksum verification."
    fi

    chmod +x "$local_bin"
    INSTALL_BIN="$local_bin"

    # Grab the branded icon alongside the binary so desktop integration ships
    # a logo, not a bare command. Verified against checksums.txt when present.
    if [ "$os" != "windows" ]; then
        if curl -fsSL --connect-timeout 10 "${BASE_URL}/shaka.png" -o "${WORK_DIR}/shaka.png"; then
            if [ -n "$hashtool" ] && [ -f "${WORK_DIR}/checksums.txt" ]; then
                local cwant cgot
                cwant=$(awk -v n="shaka.png" '$2 == n { print $1 }' "${WORK_DIR}/checksums.txt")
                if [ -n "$cwant" ]; then
                    cgot=$($hashtool "${WORK_DIR}/shaka.png" | awk '{ print $1 }')
                    if [ "$cwant" = "$cgot" ]; then
                        ok "SHA-256 verified for shaka.png"
                    else
                        warn "Icon checksum mismatch; desktop icon will be skipped."
                        rm -f "${WORK_DIR}/shaka.png"
                    fi
                fi
            fi
        else
            warn "Could not fetch shaka.png; desktop icon will be skipped."
        fi
    fi

    return 0
}

# ---------------------------------------------------------------------------
# Fallback: build from source (requires Go)
# ---------------------------------------------------------------------------
install_from_source() {
    if ! command -v go >/dev/null 2>&1; then
        die "No prebuilt binary available and Go is not installed. Install Go 1.22+ from https://go.dev and re-run this script."
    fi

    # Running inside a checkout of the repo? Build straight from the working
    # tree so offline and pre-release installs need no network and no curl.
    if [ -f "$PWD/go.mod" ]; then
        info "Building from the local checkout ($PWD)..."
        if CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${WORK_DIR}/shaka-src" ./cmd/shaka; then
            INSTALL_BIN="${WORK_DIR}/shaka-src"
            return 0
        else
            warn "Local checkout build failed; trying the source tarball."
        fi
    fi

    if ! command -v curl >/dev/null 2>&1; then
        die "curl is required to fetch the source tarball."
    fi

    info "Building from source with $(go version | awk '{print $3}')..."
    if ! curl -fsSL --connect-timeout 10 "https://codeload.github.com/${REPO}/tar.gz/refs/heads/master" -o "${WORK_DIR}/src.tar.gz"; then
        warn "Could not download the source tarball."
        return 1
    fi
    mkdir -p "${WORK_DIR}/src"
    tar -xzf "${WORK_DIR}/src.tar.gz" -C "${WORK_DIR}/src" --strip-components=1

    if ! (cd "${WORK_DIR}/src" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${WORK_DIR}/shaka-src" ./cmd/shaka); then
        warn "Source build failed."
        return 1
    fi
    INSTALL_BIN="${WORK_DIR}/shaka-src"
    return 0
}

# ---------------------------------------------------------------------------
# Place the binary on the system
# ---------------------------------------------------------------------------
install_binary() {
    local dest="$1"

    if [ ! -x "$INSTALL_BIN" ]; then
        die "No binary to install."
    fi

    if [ "$dest" = "/usr/local/bin" ] && [ ! -w "$dest" ]; then
        if sudo -n true 2>/dev/null; then
            sudo -n install -m 0755 "$INSTALL_BIN" "$dest/shaka"
        else
            dest="$DEFAULT_BIN_DIR"
        fi
    fi

    mkdir -p "$dest"
    if [ -w "$dest" ]; then
        install -m 0755 "$INSTALL_BIN" "$dest/shaka"
    elif sudo -n true 2>/dev/null; then
        sudo -n install -m 0755 "$INSTALL_BIN" "$dest/shaka"
    else
        die "Cannot write to ${dest} and sudo is not available non-interactively. Install manually."
    fi
    echo "$dest"
}

# ---------------------------------------------------------------------------
# Add the install dir to the user's PATH via their shell config (idempotent)
# ---------------------------------------------------------------------------
configure_path() {
    local dest="$1" rc="$2"

    if [[ ":$PATH:" == *":$dest:"* ]]; then
        ok "Already on PATH: ${dest}"
        return
    fi

    local line
    case "$rc" in
        *.fish) line="set -gx PATH \$PATH $dest" ;;
        *)      line="export PATH=\"\$PATH:$dest\"" ;;
    esac

    if [ -f "$rc" ] && grep -qsF "$dest" "$rc"; then
        ok "${dest} already configured in ${rc}"
        return
    fi

    printf '\n# added by SHAKA installer\n%s\n' "$line" >> "$rc"
    warn "Added ${dest} to your PATH in ${rc}"
    warn "Run: source ${rc}  (or open a new terminal) to use 'shaka'"
}

# ---------------------------------------------------------------------------
# Desktop integration (Linux only): install the app icon and a .desktop entry
# so shaka shows up with its logo in GNOME's search/app grid. Data goes next
# to the binary:  ~/.local/bin -> ~/.local/share,  /usr/local/bin -> /usr/local/share
# ---------------------------------------------------------------------------
install_desktop_integration() {
    [ "$(uname -s)" = "Linux" ] || return 0

    local dest="$1" dataroot icon_dir apps_dir
    case "$dest" in
        */bin) dataroot="$(dirname "$dest")/share" ;;
        *)     dataroot="$dest/share" ;;
    esac
    icon_dir="$dataroot/icons/hicolor/512x512/apps"
    apps_dir="$dataroot/applications"

    local icon_src="${WORK_DIR}/shaka.png"
    if [ -f "$PWD/assets/shaka.png" ]; then
        icon_src="$PWD/assets/shaka.png"
    elif [ ! -f "$icon_src" ] && [ -f "${WORK_DIR}/src/assets/shaka.png" ]; then
        icon_src="${WORK_DIR}/src/assets/shaka.png"
    fi

    if [ ! -f "$icon_src" ]; then
        warn "No icon found; skipping desktop integration."
        return 0
    fi

    mkdir -p "$icon_dir" "$apps_dir"
    install -m 0644 "$icon_src" "$icon_dir/shaka.png"

    local desktop="$apps_dir/shaka.desktop"
    if [ ! -f "$desktop" ]; then
        cat >"$desktop" <<EOF
[Desktop Entry]
Type=Application
Name=SHAKA
GenericName=AI-Assisted Vulnerability Discovery Tool
Comment=Automated reconnaissance and prioritised vulnerability discovery
Exec=$dest/shaka
Icon=$icon_dir/shaka.png
Terminal=true
Categories=Utility;Network;Security;Development;
Keywords=vulnerability;scanning;recon;security;pentest;ai;
EOF
    fi
    chmod 0644 "$desktop"
    ok "Installed desktop entry: ${desktop}"
    ok "Installed app icon: ${icon_dir}/shaka.png"

    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$apps_dir" >/dev/null 2>&1 || true
    command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache "$dataroot/icons/hicolor" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Verify the installation
# ---------------------------------------------------------------------------
verify() {
    local dest="$1"
    local bin="$dest/shaka"

    if [ ! -x "$bin" ]; then
        warn "shaka binary not found at ${bin}."
        return 1
    fi

    info "Verifying installation..."
    "$bin" version 2>/dev/null || "$bin" --help >/dev/null 2>&1
    ok "SHAKA installed at ${bin}"
    ok "Run 'shaka --help' to get started."
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    banner

    local os arch rc dest
    os=$(detect_os)
    arch=$(detect_arch)
    rc=$(detect_shell_rc)

    WORK_DIR=$(mktemp -d)
    trap 'rm -rf "$WORK_DIR"' EXIT

    if [ "$os" = "windows" ]; then
        dest="$HOME/bin"
    else
        dest="$DEFAULT_BIN_DIR"
    fi

    INSTALL_BIN=""

    if ! install_release "$os" "$arch"; then
        if ! install_from_source; then
            die "Installation failed. Please check your connection and try again."
        fi
    fi

    local final_dest
    final_dest=$(install_binary "$dest")

    configure_path "$final_dest" "$rc"

    install_desktop_integration "$final_dest"

    if verify "$final_dest"; then
        log "Done."
    else
        die "Installation may need a new terminal session."
    fi
}

main "$@"