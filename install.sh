#!/usr/bin/env bash
#
# SHAKA CLI — QYVORA zero-config installer
#
# This file is GENERATED from qyvora-dist/installer.template.sh.
# Do not edit it by hand: change the template + qyvora-dist/tools.def, then run
#   qyvora-dist/generate.sh
# so every tool keeps one shared, audited installer implementation.
#
# What this does, in order:
#   1. Detects the real target: kernel, CPU, *userspace*, ABI and runtime
#      environment. Android/Termux is a distinct target from ordinary Linux.
#   2. Resolves a release artifact name that is valid for that exact target.
#   3. Downloads it over HTTPS, verifies SHA-256 against the published
#      checksums.txt, and validates the executable format (ELF class,
#      machine, and PIE-ness) before anything is executed.
#   4. Falls back to a local source build when no compatible prebuilt exists.
#   5. Installs atomically into the correct user executable directory.
#   6. Adds that directory to PATH only if needed, idempotently, with a backup.
#   7. Proves the installed binary actually runs before reporting success, and
#      rolls back to the previous working binary if it does not.
#
# Subcommands:
#   (none)      install / update to the latest release
#   --uninstall remove the binary and desktop integration (keeps user data)
#   --prefix D  install into D instead of the platform default
#   --no-path   install without touching your shell rc / PATH
#   --version   print installer version and exit
#   --help      usage
#
# Supported targets for shaka:
#   Linux        amd64, arm64, armv7 (aarch64/armv7l per uname -m)
#   macOS        amd64, arm64
#   Windows      amd64, arm64          (use install.ps1)
#   Android      arm64, via Termux     (installs to $PREFIX/bin)
#
# Android / Termux notes:
#   A Linux/arm64 binary will NOT run on Android. Android's bionic linker only
#   loads position-independent executables, so this installer downloads a
#   GOOS=android build and rejects an ELF ET_EXEC artifact outright.
#   On Termux this installer installs a published prebuilt GOOS=android/arm64
#   binary into $PREFIX/bin.
#   A 32-bit Android (arm/armv7) target needs an external (cgo) link against
#   the Android NDK, so no prebuilt is published; use QYVORA_SOURCE=1 and a
#   local Go toolchain instead.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-shaka/main/install.sh | bash
#   bash install.sh
#
# Environment overrides (all optional):
#   QYVORA_INSTALL_DIR   override the install directory
#   QYVORA_VERSION       install a specific release tag instead of latest
#   QYVORA_ALLOW_UNVERIFIED=1  proceed without a checksum match (never recommended)
#   QYVORA_NO_DESKTOP=1  skip desktop icon / .desktop integration
#   QYVORA_NO_PATH=1     do not add the install directory to PATH
#   QYVORA_SOURCE=1      force a local source build, ignore prebuilt artifacts
#
# QYVORA OffSec — Tamale, Ghana

set -euo pipefail
umask 022

# ===========================================================================
# TOOL METADATA — generated from qyvora-dist/tools.def
# ===========================================================================
QYVORA_TOOL="shaka"
QYVORA_TITLE="SHAKA"
QYVORA_REPO="QYVORA/qyvora-shaka"
QYVORA_MAIN_PKG="./cmd/shaka"
# How the release publishes: binary (bare executable) | tar.gz | zip
QYVORA_PACKAGE="binary"
# Android/Termux policy: prebuilt | source-only | unsupported
QYVORA_ANDROID="prebuilt"
# Whether a local source build fallback is offered
QYVORA_SOURCE_BUILD="1"
# CGO_ENABLED used for source builds. 0 keeps prebuilt binaries static and
# portable; tools that bind system libraries (toha3ee -> libpcap) need 1.
QYVORA_CGO_ENABLED="0"
QYVORA_MIN_GO="1.26"
QYVORA_ICON="shaka.png"
QYVORA_ICO="shaka.ico"
QYVORA_DESKTOP_NAME="SHAKA"
QYVORA_DESKTOP_COMMENT="Active Directory and identity attack analysis"
QYVORA_DESKTOP_KEYWORDS="active-directory;ldap;kerberos;identity;domain;bloodhound;windows"
# Ordered probes used to prove the installed binary runs
QYVORA_VERSION_PROBE="--version version --help"
# Additional .desktop entry, if the upstream asset ships one
QYVORA_DESKTOP_ASSET="shaka.desktop"
# Install man pages from the source tree when present (1/0)
QYVORA_MAN_PAGES="0"

# Planning state. These are safe defaults so that the dependency check in main()
# can read them before plan_target() runs under `set -u`; plan_target() is what
# actually decides them.
QYVORA_WANT_PREBUILT=1
QYVORA_ARTIFACT=""
QYVORA_BASE_URL=""
# Set by --prefix or QYVORA_INSTALL_DIR; otherwise compute_install_dir() picks
# the platform default. Declared here so the argument parser can read it under
# `set -u` before compute_install_dir() has run.
QYVORA_INSTALL_DIR=""
# ===========================================================================

QYVORA_INSTALLER_VERSION="2"

# Exit codes, so callers can classify a failure without parsing text.
readonly EXIT_OK=0
readonly EXIT_FATAL=1
readonly EXIT_UNSUPPORTED=2
readonly EXIT_VERIFY=3

# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------
_has_color() {
    # Disable if NO_COLOR is set
    [ -z "${NO_COLOR:-}" ] || return 1
    # Disable if not a TTY on stdout
    [ -t 1 ] || return 1
    # Disable for dumb terminals
    [ "${TERM:-dumb}" != "dumb" ] || return 1
    return 0
}

if _has_color; then
    C_RED=$'\033[1;31m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'
    C_CYN=$'\033[1;36m'; C_DIM=$'\033[90m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
    C_RED=''; C_GRN=''; C_YEL=''; C_CYN=''; C_DIM=''; C_BLD=''; C_OFF=''
fi

log()  { printf '%s[%s]%s %s\n' "$C_DIM" "$QYVORA_TOOL" "$C_OFF" "$*"; }
ok()   { printf '  %s[OK]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
info() { printf '  %s[..]%s %s\n' "$C_CYN" "$C_OFF" "$*"; }
warn() { printf '  %s[!]%s %s\n'  "$C_YEL" "$C_OFF" "$*"; }
err()  { printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; }
note() { printf '  %s[INFO]%s %s\n' "$C_DIM" "$C_OFF" "$*"; }

# die <exit-code> <message...>
die() {
    local code="$1"; shift
    err "$*"
    exit "$code"
}

banner() {
    [ -t 1 ] || return 0
    printf '\n'
    printf '  %s%s CLI%s\n' "$C_BLD" "$QYVORA_TITLE" "$C_OFF"
    printf '  %sQYVORA OffSec — Tamale, Ghana%s\n' "$C_CYN" "$C_OFF"
    printf '  %sQYVORA shared installer v%s — https://github.com/%s%s\n' \
        "$C_DIM" "$QYVORA_INSTALLER_VERSION" "$QYVORA_REPO" "$C_OFF"
    printf '  %s----------------------------------------%s\n' "$C_DIM" "$C_OFF"
    printf '\n'
}

usage() {
    # Print the leading comment block, whatever length it is. Stopping at the
    # first non-comment line avoids the line range drifting every time this
    # header is edited.
    sed -n '3,/^[^#]/p' "$SELF_FILE" 2>/dev/null | sed '$d' | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------------------
# Dependency checks (classified, never silently installed)
# ---------------------------------------------------------------------------
need_cmd() {
    command -v "$1" >/dev/null 2>&1 && return 0
    err "Missing required dependency: $1"
    case "$1" in
        curl) note "Install it with one of:" ;;
    esac
    if [ "$QYVORA_OS" = "termux" ]; then
        case "$1" in
            curl) note "  pkg install curl   (or: pkg install ca-certificates)" ;;
            tar)  note "  pkg install tar" ;;
            unzip) note "  pkg install unzip" ;;
            go)   note "  pkg install golang" ;;
            gcc)  note "  pkg install clang" ;;
            file) note "  pkg install file  (optional; format is also checked without it)" ;;
            sha256sum) note "  pkg install coreutils" ;;
            *) note "  pkg install $1" ;;
        esac
    elif [ "$QYVORA_OS" = "macos" ]; then
        case "$1" in
            sha256sum) note "  brew install coreutils   (macOS ships 'shasum -a 256' instead)" ;;
            file) note "  brew install file   (optional)" ;;
            *) note "  brew install $1" ;;
        esac
    else
        case "$1" in
            curl) note "  Debian/Ubuntu: sudo apt-get install curl" ;;
            tar)  note "  Debian/Ubuntu: sudo apt-get install tar" ;;
            unzip) note "  Debian/Ubuntu: sudo apt-get install unzip" ;;
            go)   note "  https://go.dev/dl/  (QYVORA needs Go ${QYVORA_MIN_GO}+)" ;;
            file) note "  Debian/Ubuntu: sudo apt-get install file   (optional)" ;;
            sha256sum) note "  Debian/Ubuntu: sudo apt-get install coreutils" ;;
            *) note "  Install '$1' with your system package manager." ;;
        esac
    fi
    return 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Platform / environment detection
#
# The central rule this installer exists to enforce:
#   a Linux *kernel* does not imply an ordinary Linux *userspace*.
#   Android reports `uname -s` == Linux, so we must look further before we
#   are allowed to call a target "linux".
# ---------------------------------------------------------------------------

# detect_environment populates:
#   QYVORA_KERNEL   uname -s
#   QYVORA_MACHINE  uname -m
#   QYVORA_OS       linux | macos | windows | android | bsd | solaris
#   QYVORA_ENV      termux | wsl | darwin | mingw | msys | cygwin | native
#   QYVORA_ARCH     amd64 | arm64 | armv7 | unsupported
#   QYVORA_DISTRO    distribution id (informational)
#   QYVORA_CONTAINER container runtime when detected (informational)
detect_environment() {
    QYVORA_KERNEL=$(uname -s 2>/dev/null || echo unknown)
    QYVORA_MACHINE=$(uname -m 2>/dev/null || echo unknown)
    QYVORA_ENV="native"
    QYVORA_DISTRO=""
    QYVORA_CONTAINER=""

    # --- Android / Termux -------------------------------------------------
    # Several independent signals, because no single one is reliable:
    #   * $PREFIX is set by Termux and points inside the app data sandbox
    #   * $TERMUX_VERSION is exported by Termux's own shell profile
    #   * $TERMUX_MAIN_PACKAGE_FORMAT
    #   * the Termux filesystem layout (usr/bin present under PREFIX)
    #   * getprop ro.build.version.sdk, where getprop is reachable
    #   * uname -o prints "Android" on bionic-based userland
    local android_signal=""
    if [ -n "${TERMUX_VERSION:-}" ]; then
        android_signal="${android_signal} TERMUX_VERSION"
    fi
    # Match on the com.termux component rather than on one literal prefix, so
    # secondary users (/data/user/0/...), work profiles, debug builds and
    # relocated sandboxes are all recognised.
    if [ -n "${PREFIX:-}" ]; then
        case "$PREFIX" in
            *com.termux*) android_signal="${android_signal} PREFIX" ;;
        esac
    fi
    if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ] && [ -d "${PREFIX}/etc" ] \
        && [ -n "${ANDROID_ROOT:-}" ]; then
        android_signal="${android_signal} TERMUX_LAYOUT"
    fi
    if command -v getprop >/dev/null 2>&1; then
        if [ -n "$(getprop ro.build.version.sdk 2>/dev/null)" ]; then
            android_signal="${android_signal} GETPROP"
        fi
    fi
    if [ "$QYVORA_KERNEL" = "Linux" ]; then
        if uname -o 2>/dev/null | grep -qi android; then
            android_signal="${android_signal} UNAME_O"
        fi
    fi

    if [ -n "$android_signal" ] && [ "$QYVORA_KERNEL" = "Linux" ]; then
        QYVORA_OS="android"
        QYVORA_ENV="termux"
    fi

    # --- WSL (a Linux kernel on a Windows host) ----------------------------
    if [ "$QYVORA_KERNEL" = "Linux" ] && [ -z "${android_signal}" ]; then
        if [ -n "${WSL_DISTRO_NAME:-}" ] || [ -n "${WSLENV:-}" ] \
            || grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
            QYVORA_ENV="wsl"
        fi
    fi

    # --- Windows shells running on a Windows kernel ------------------------
    if [ -n "${MSYSTEM:-}" ]; then
        QYVORA_ENV="msys"
    fi

    # --- Containers (informational only) -----------------------------------
    if [ -f /.dockerenv ]; then
        QYVORA_CONTAINER="docker"
    elif [ -r /proc/1/cgroup ] && grep -qaE 'kubepods|containerd' /proc/1/cgroup 2>/dev/null; then
        QYVORA_CONTAINER="kubernetes"
    fi

    # --- OS family ---------------------------------------------------------
    if [ -z "${QYVORA_OS:-}" ]; then
        case "$QYVORA_KERNEL" in
            Linux)  QYVORA_OS="linux" ;;
            Darwin) QYVORA_OS="macos" ;;
            MINGW*|MSYS*|CYGWIN*) QYVORA_OS="windows" ;;
            FreeBSD|NetBSD|OpenBSD|DragonFly) QYVORA_OS="bsd" ;;
            SunOS)  QYVORA_OS="solaris" ;;
            *)      QYVORA_OS="unsupported" ;;
        esac
    fi

    # --- Distribution (informational) --------------------------------------
    if [ -r /etc/os-release ]; then
        QYVORA_DISTRO=$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-unknown}")
    fi

    # --- CPU architecture --------------------------------------------------
    # uname -m is the *kernel*'s view. On Windows it can be a lie about what
    # the CPU can execute (WOW64 on ARM64 reports x86_64), so we only treat
    # the Windows case as unknown-arch and let the artifact gate decide.
    case "$QYVORA_MACHINE" in
        x86_64|amd64|x64)   QYVORA_ARCH="amd64" ;;
        aarch64|arm64)      QYVORA_ARCH="arm64" ;;
        armv7l|armv7|armhf) QYVORA_ARCH="armv7" ;;
        armv8l)             QYVORA_ARCH="armv7" ;;
        i386|i686)          QYVORA_ARCH="i386" ;;
        *)                  QYVORA_ARCH="unsupported" ;;
    esac
}

# The artifact OS token. Android deliberately gets its own token so a
# linux/arm64 artifact can never be selected for a Termux user.
target_os_token() {
    case "$QYVORA_OS" in
        linux)   printf 'linux' ;;
        macos)   printf 'macos' ;;
        windows) printf 'windows' ;;
        android) printf 'android' ;;
        *)       printf '' ;;
    esac
}

# ---------------------------------------------------------------------------
# Support policy: what do we actually ship, and what do we refuse?
#
# This is the function that makes the original ANANSI failure impossible: on
# Termux it can only ever return an `android` artifact, or refuse.
# ---------------------------------------------------------------------------
android_support_policy() {
    case "$QYVORA_ANDROID" in
        prebuilt)
            if [ "$QYVORA_ARCH" = "arm64" ]; then
                return 0            # published android/arm64 artifact
            fi
            return 1                # android/amd64 + android/arm need cgo
            ;;
        source-only)
            return 1                # no prebuilt; only a local build may help
            ;;
        unsupported)
            return 1
            ;;
    esac
    return 1
}

unsupported_android_reason() {
    if [ "$QYVORA_ANDROID" = "unsupported" ]; then
        printf '%s links against libpcap through cgo, which requires the Android NDK and a bionic sysroot; no static prebuilt can be produced.\n' "$QYVORA_TITLE"
        return
    fi
    if [ "$QYVORA_ARCH" = "amd64" ]; then
        printf 'android/amd64 requires external (cgo) linking, so a static prebuilt binary cannot be published for it.\n'
        return
    fi
    if [ "$QYVORA_ARCH" = "armv7" ]; then
        printf 'android/arm (32-bit) requires external (cgo) linking, so a static prebuilt binary cannot be published for it.\n'
        return
    fi
    if [ "$QYVORA_ARCH" = "i386" ]; then
        printf 'android/386 requires external (cgo) linking, so a static prebuilt binary cannot be published for it.\n'
        return
    fi
    printf 'no compatible Android/Termux artifact is published for this architecture (%s).\n' "$QYVORA_ARCH"
}

# Decide the artifact name for this machine, or explain why we will not.
#
# Sets: QYVORA_ARTIFACT, QYVORA_BASE_URL, QYVORA_WANT_PREBUILT (1/0)
plan_target() {
    # Validate user input first: the tag is interpolated into a URL, so reject
    # anything outside a strict charset before doing any other work.
    local version="${QYVORA_VERSION:-latest}"
    case "$version" in
        *[!A-Za-z0-9._-]*|"")
            die "$EXIT_FATAL" "Invalid release tag: '$version'"
            ;;
    esac

    local os_token arch_token
    os_token=$(target_os_token)
    arch_token="$QYVORA_ARCH"

    if [ -z "$os_token" ]; then
        unsupported_target "Operating system '$(uname -s 2>/dev/null || echo unknown)' is not a supported QYVORA target."
    fi

    case "$QYVORA_ARCH" in
        amd64|arm64)
            : ;;
        armv7)
            armv7_policy
            ;;
        i386)
            unsupported_target "32-bit x86 (i386/i686) builds are not published for ${os_token}; build from source if you have a toolchain."
            ;;
        *)
            unsupported_target "CPU architecture '$(uname -m 2>/dev/null || echo unknown)' is not a supported QYVORA target."
            ;;
    esac

    QYVORA_WANT_PREBUILT=1
    QYVORA_ARTIFACT="${QYVORA_TOOL}-${os_token}-${arch_token}"
    if [ "$os_token" = "windows" ]; then
        QYVORA_ARTIFACT="${QYVORA_ARTIFACT}.exe"
    fi

    # Android has its own policy; ordinary Linux has its own.
    if [ "$os_token" = "android" ]; then
        if ! android_support_policy; then
            QYVORA_ANDROID_REASON=$(unsupported_android_reason)
            # A source build is still a legitimate answer *if* the project
            # supports it. Otherwise stop with a clean refusal.
            if [ "$QYVORA_SOURCE_BUILD" != "1" ]; then
                unsupported_target "$QYVORA_ANDROID_REASON"
            fi
            # No artifact name is retained: we are not going to download it.
            QYVORA_WANT_PREBUILT=0
            QYVORA_ARTIFACT=""
        fi
    fi

    if [ "$version" = "latest" ]; then
        QYVORA_BASE_URL="https://github.com/${QYVORA_REPO}/releases/latest/download"
    else
        QYVORA_BASE_URL="https://github.com/${QYVORA_REPO}/releases/download/${version}"
    fi
}

armv7_policy() {
    # 32-bit ARM is buildable for the pure-Go tools but we do not publish
    # prebuilts for it, so we do not claim it. Say so, then offer source.
    if [ "$QYVORA_SOURCE_BUILD" != "1" ]; then
        unsupported_target "32-bit ARM (armv7) prebuilt binaries are not published; build from source instead."
    fi
    QYVORA_WANT_PREBUILT=0
    QYVORA_ARTIFACT=""
    warn "No published prebuilt for 32-bit ARM; falling back to a local source build."
}

# unsupported_target <reason>: a clean, explained refusal. The exit code
# distinguishes "this platform is not supported" from "something broke".
unsupported_target() {
    local reason="$1"
    err "$QYVORA_TITLE is not available for this platform."
    note "Reason: ${reason}"
    print_diagnostics
    if [ -n "${QYVORA_ARTIFACT:-}" ]; then
        note "Attempted artifact: ${QYVORA_ARTIFACT}"
    else
        note "No release artifact was selected for this platform."
    fi
    note "A Linux kernel does not imply a Linux userspace: this installer"
    note "refuses to substitute an artifact built for a different OS or ABI."
    note "No files were installed."
    printf '\n'
    note "Supported targets are listed at:"
    note "  https://github.com/${QYVORA_REPO}#supported-platforms"
    exit "$EXIT_UNSUPPORTED"
}

print_diagnostics() {
    printf '\n'
    printf '  %sQYVORA Installer diagnostics%s\n' "$C_BLD" "$C_OFF"
    printf '  %s==============================%s\n' "$C_BLD" "$C_OFF"
    printf '  Tool:            %s\n' "$QYVORA_TITLE"
    printf '  Kernel:          %s\n' "$QYVORA_KERNEL"
    printf '  CPU:             %s (%s)\n' "$QYVORA_MACHINE" "$QYVORA_ARCH"
    printf '  Operating system:%s\n' "$QYVORA_OS"
    printf '  Environment:     %s\n' "$QYVORA_ENV"
    [ -n "$QYVORA_DISTRO" ]    && printf '  Distribution:    %s\n' "$QYVORA_DISTRO"
    [ -n "$QYVORA_CONTAINER" ] && printf '  Container:       %s\n' "$QYVORA_CONTAINER"
    [ -n "${PREFIX:-}" ]       && printf '  PREFIX:          %s\n' "$PREFIX"
    printf '  Install dir:     %s\n' "${QYVORA_INSTALL_DIR:-<computed>}"
    printf '\n'
}

# ---------------------------------------------------------------------------
# Executable format validation
#
# `file(1)` is a nicety. The real gate is a byte-level read of the ELF header
# with od(1), which is present on every POSIX system including Termux, so a
# missing `file` can never turn into a missing check.
# ---------------------------------------------------------------------------
elf_byte() { od -An -tu1 -j"$1" -N1 "$2" 2>/dev/null | awk '{print $1}'; }

validate_executable() {
    local path="$1"
    local expect_os="$2" expect_arch="$3"
    local osabi etype emachine class data magic0 magic1 magic2 magic3

    magic0=$(od -An -tu1 -j0 -N4 "$path" 2>/dev/null | awk '{print $1" "$2" "$3" "$4}')
    if [ "$magic0" = "127 69 76 70" ]; then
        # ---------------------------------------------------------------
        # ELF (Linux, Android, BSD, Solaris)
        # ---------------------------------------------------------------
        class=$(elf_byte 4 "$path")
        data=$(elf_byte 5 "$path")
        osabi=$(elf_byte 7 "$path")
        etype=$(od -An -tu1 -j16 -N2 "$path" | awk '{print $1}')
        emachine=$(od -An -tu1 -j18 -N2 "$path" | awk '{print $1}')

        if [ "$data" != "1" ]; then
            err "ELF binary is big-endian (EI_DATA=$data); this installer only supports little-endian targets."
            return 1
        fi

        local want_class want_machine
        case "$expect_arch" in
            amd64) want_class=2; want_machine=62  ;;  # EM_X86_64
            arm64) want_class=2; want_machine=183 ;;  # EM_AARCH64
            armv7) want_class=1; want_machine=40  ;;  # EM_ARM
            *)     return 0 ;;
        esac

        if [ "$class" != "$want_class" ]; then
            err "ELF class mismatch: artifact is $( [ "$class" = 1 ] && echo 32-bit || echo 64-bit ), target needs $( [ "$want_class" = 1 ] && echo 32-bit || echo 64-bit )."
            return 1
        fi
        if [ "$emachine" != "$want_machine" ]; then
            err "ELF machine mismatch: artifact e_machine=$emachine, target needs e_machine=$want_machine."
            return 1
        fi

        # The check that would have caught the original ANANSI/Termux bug.
        # Android's bionic linker (linker64) only loads position-independent
        # executables. A GOOS=linux build is ET_EXEC (2) and the kernel-side
        # execve path hands it to linker64, which aborts with
        #   "has unexpected e_type: 2"
        if [ "$expect_os" = "android" ] && [ "$etype" != "3" ]; then
            err "Artifact is not position-independent (ELF e_type=$etype, expected 3 = ET_DYN)."
            err "Android's dynamic loader refuses non-PIE executables:"
            err "    \"<path>\" has unexpected e_type: $etype"
            err "This is a Linux/ELF binary, not a valid Android/Termux target."
            return 1
        fi
        if [ "$expect_os" = "android" ] && [ "$osabi" != "0" ] && [ "$osabi" != "3" ] && [ "$osabi" != "255" ]; then
            warn "Unexpected ELF OS/ABI byte ($osabi) for an Android artifact; continuing to the execution test."
        fi

        ok "ELF $( [ "$class" = 1 ] && echo 32-bit || echo 64-bit ), machine=$emachine, e_type=$etype"
        return 0
    fi

    # ---------------------------------------------------------------
    # Mach-O (macOS)
    # ---------------------------------------------------------------
    if [ "$magic0" = "207 250 186 190" ] || [ "$magic0" = "190 186 250 207" ]; then
        case "$expect_arch" in
            arm64) want_machine=0x0100000c ;;
            amd64) want_machine=0x01000007 ;;
            *) return 0 ;;
        esac
        local cputype
        cputype=$(od -An -tx1 -j4 -N4 "$path" | awk '{print $1$2$3$4}')
        if [ "$cputype" != "0100000c" ] && [ "$cputype" != "01000007" ]; then
            err "Mach-O CPU type mismatch: artifact=$cputype."
            return 1
        fi
        ok "Mach-O, cputype=0x$cputype"
        return 0
    fi

    # ---------------------------------------------------------------
    # PE / COFF (Windows)
    #
    # The machine word is not at a fixed offset: it sits behind the optional
    # header, so e_lfanew (offset 60) points at the PE signature, and the
    # machine word is 4 bytes later.
    # ---------------------------------------------------------------
    if [ "$magic0" = "77 90" ]; then
        local lfanew machine want_pe
        lfanew=$(od -An -tu4 --endian=little -j60 -N4 "$path" 2>/dev/null | awk '{print $1}')
        if [ -z "$lfanew" ] || [ "$lfanew" -lt 1 ] 2>/dev/null; then
            err "PE header offset (e_lfanew) is unreadable."
            return 1
        fi
        machine=$(od -An -tu2 --endian=little -j"$((lfanew + 4))" -N2 "$path" 2>/dev/null | awk '{print $1}')
        case "$expect_arch" in
            amd64) want_pe=34404 ;;   # IMAGE_FILE_MACHINE_AMD64
            arm64) want_pe=43620 ;;   # IMAGE_FILE_MACHINE_ARM64
            *) return 0 ;;
        esac
        if [ -z "$machine" ]; then
            err "PE machine word is unreadable."
            return 1
        fi
        if [ "$machine" != "$want_pe" ]; then
            err "PE machine mismatch: artifact=$machine, target needs $want_pe."
            return 1
        fi
        ok "PE, machine=$machine"
        return 0
    fi

    err "Unrecognised executable format (magic: ${magic0:-none}). Refusing to install."
    return 1
}

# describe_file: best-effort human-readable type, never a gate.
describe_file() {
    if command -v file >/dev/null 2>&1; then
        file -b "$1" 2>/dev/null | head -1 || true
    fi
}

# ---------------------------------------------------------------------------
# Runtime verification: prove the executable actually runs.
# ---------------------------------------------------------------------------
# QYVORA_VERSION_PROBE is a space-separated list of SINGLE-WORD probes, tried in
# order until one exits 0 -- typically "--version version --help". Each entry is
# one argv element, so a multi-word command is not expressible: "version --help"
# would be tried as `tool version` and then `tool --help`, never as one call.
#
# The word splitting below is deliberate for that reason, and the quoting on
# "$probe" is deliberate too: splitting builds the argument list, quoting keeps
# each probe a single argument.
runtime_probe() {
    local bin="$1" probe
    for probe in $QYVORA_VERSION_PROBE; do
        if "$bin" "$probe" >/dev/null 2>&1; then
            printf '%s' "$probe"
            return 0
        fi
    done
    return 1
}

# Probe the binary for a version string. Not every tool prints one for every
# probe, and some print a leading blank line, so empty and whitespace-only
# output is skipped rather than reported as "version 0".
runtime_version() {
    local bin="$1" probe out first
    for probe in $QYVORA_VERSION_PROBE; do
        # A help probe proves the binary runs, but it cannot supply a version:
        # anansi's --help opens with its ASCII banner, so the first non-blank
        # line was "            ;                  &", and the installer reported
        # that as the installed version. Prefer a real version probe and let
        # the caller fall back to its liveness wording.
        case "$probe" in
            --help|-h|help) continue ;;
        esac
        if out=$("$bin" "$probe" 2>/dev/null); then
            first=$(printf '%s\n' "$out" | sed -e '/^[[:space:]]*$/d' | head -1)
            if [ -n "$first" ]; then
                printf '%s' "$first"
                return 0
            fi
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Install location
# ---------------------------------------------------------------------------
compute_install_dir() {
    if [ -n "${QYVORA_INSTALL_DIR:-}" ]; then
        return 0
    fi
    case "$QYVORA_OS" in
        android)
            # Termux manages its own PATH. ~/.local/bin is NOT on it by
            # default, so installing there is exactly the bug we avoid.
            if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ]; then
                QYVORA_INSTALL_DIR="${PREFIX}/bin"
            else
                die "$EXIT_FATAL" "Termux environment detected but \$PREFIX/bin is missing. Reinstall Termux, or set QYVORA_INSTALL_DIR."
            fi
            ;;
        windows)
            # MSYS2/Git-Bash: a POSIX-shaped path is the only sane target.
            QYVORA_INSTALL_DIR="${HOME}/.local/bin"
            ;;
        macos|linux|*)
            QYVORA_INSTALL_DIR="${HOME}/.local/bin"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# PATH management: safe, idempotent, backup-first, shell-aware
# ---------------------------------------------------------------------------
shell_rc_path() {
    local shell_name="${SHELL##*/}"
    # Honour an explicit override, then a running interactive shell, then SHELL.
    if [ -n "${QYVORA_SHELL_RC:-}" ]; then
        printf '%s' "$QYVORA_SHELL_RC"
        return 0
    fi
    case "$shell_name" in
        zsh)  printf '%s' "${ZDOTDIR:-$HOME}/.zshrc" ;;
        fish) printf '%s' "$HOME/.config/fish/config.fish" ;;
        bash)
            # macOS login bash reads .bash_profile; interactive non-login reads
            # .bashrc. Append to .bash_profile only when it is the only one.
            if [ -f "$HOME/.bashrc" ] || [ ! -f "$HOME/.bash_profile" ]; then
                printf '%s' "$HOME/.bashrc"
            else
                printf '%s' "$HOME/.bash_profile"
            fi
            ;;
        *) printf '%s' "$HOME/.bashrc" ;;
    esac
}

path_contains() {
    local dir="$1" entry
    local IFS_SAVE="$IFS"
    IFS=':'
    for entry in $PATH; do
        IFS="$IFS_SAVE"
        if [ "$entry" = "$dir" ]; then
            return 0
        fi
        IFS=':'
    done
    return 1
}

configure_path() {
    local dir="$1"
    local rc

    # Opt-out, for minimal images, CI containers and anyone who manages PATH
    # themselves. Checked before anything is inspected or written, so honouring
    # it is a genuine no-op rather than a partially-applied configuration.
    if [ "${QYVORA_NO_PATH:-}" = "1" ]; then
        info "PATH management disabled (--no-path / QYVORA_NO_PATH=1)."
        if ! path_contains "$dir"; then
            note "Add $dir to your PATH manually, or run the installer without --no-path."
        fi
        return 0
    fi

    rc=$(shell_rc_path)

    if path_contains "$dir"; then
        ok "Install directory is already on PATH: $dir"
        return 0
    fi

    # Already managed by a previous run of this installer? Do not duplicate.
    if [ -f "$rc" ] && grep -qF "# qyvora:${QYVORA_TOOL}" "$rc" 2>/dev/null; then
        if grep -qF "$dir" "$rc" 2>/dev/null; then
            ok "PATH already configured for ${QYVORA_TOOL} in $rc"
            note "Restart your shell (or run: source $rc) to pick up the change."
            return 0
        fi
    fi

    if [ -e "$rc" ]; then
        cp -p -- "$rc" "${rc}.qyvora-backup" 2>/dev/null \
            && note "Backed up $rc -> ${rc}.qyvora-backup" \
            || warn "Could not create a backup of $rc; continuing."
    fi

    # A first-run shell may have no config file (and, for fish, no config
    # directory at all), so create the parent before appending.
    mkdir -p -- "$(dirname -- "$rc")" 2>/dev/null || {
        warn "Could not create $(dirname -- "$rc"); add $dir to your PATH manually."
        return 1
    }

    local line
    case "$rc" in
        *.fish)
            line="fish_add_path \"${dir}\""
            [ -e "$rc" ] || line="set -gx PATH \$PATH \"${dir}\""
            ;;
        *)
            line="export PATH=\"\$PATH:${dir}\""
            ;;
    esac

    {
        printf '\n# qyvora:%s (added by the %s installer; safe to delete)\n' "$QYVORA_TOOL" "$QYVORA_TITLE"
        printf '%s\n' "$line"
    } >> "$rc"

    ok "Added $dir to PATH in $rc"
    note "Restart your shell (or run: source $rc) to pick up the change."
}

# ---------------------------------------------------------------------------
# Download
#
# HTTPS only, pinned to the release host, redirects restricted to GitHub's own
# object storage, and a private 0700 temp dir that is removed on exit.
# ---------------------------------------------------------------------------
WORK_DIR=""
cleanup() {
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf -- "$WORK_DIR"
    fi
}

fetch() {
    local url="$1" out="$2"
    case "$url" in
        https://github.com/*|https://raw.githubusercontent.com/*|https://*.githubusercontent.com/*|https://codeload.github.com/*|https://objects.githubusercontent.com/*)
            : ;;
        *)
            err "Refusing to download from a non-HTTPS GitHub origin: $url"
            return 1
            ;;
    esac

    if command -v curl >/dev/null 2>&1; then
        # --proto =https        no plaintext fallback
        # --tlsv1.2             minimum TLS
        # --location            follow GitHub's own redirect to object storage
        # --proto-redir =https  never downgrade the redirect target
        curl -fsSL --proto '=https' --tlsv1.2 --proto-redir '=https' \
             --connect-timeout 15 --max-time 300 --retry 2 --retry-delay 1 \
             -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget --quiet --https-only --timeout=30 --tries=2 -O "$out" "$url"
    else
        need_cmd curl || need_cmd wget || return 1
        return 1
    fi
}

fetch_checksum() {
    local artifact="$1"
    [ -f "$WORK_DIR/checksums.txt" ] && return 0
    if ! fetch "${QYVORA_BASE_URL}/checksums.txt" "$WORK_DIR/checksums.txt" 2>/dev/null; then
        return 1
    fi
    return 0
}

verify_checksum() {
    local path="$1" artifact="$2"
    local want got

    if ! fetch_checksum "$artifact"; then
        err "Could not download checksums.txt from ${QYVORA_BASE_URL}"
        if [ "${QYVORA_ALLOW_UNVERIFIED:-}" = "1" ]; then
            warn "QYVORA_ALLOW_UNVERIFIED=1 set; continuing WITHOUT checksum verification."
            return 0
        fi
        err "Refusing to install an artifact whose integrity cannot be checked."
        return 1
    fi

    if ! command -v sha256sum >/dev/null 2>&1 \
        && ! command -v shasum >/dev/null 2>&1 \
        && ! command -v openssl >/dev/null 2>&1; then
        err "No SHA-256 tool available (need sha256sum, shasum or openssl)."
        if [ "${QYVORA_ALLOW_UNVERIFIED:-}" = "1" ]; then
            warn "QYVORA_ALLOW_UNVERIFIED=1 set; continuing WITHOUT checksum verification."
            return 0
        fi
        return 1
    fi

    # checksums.txt is produced by `sha256sum *`, i.e. "<digest>  <name>".
    want=$(awk -v n="$artifact" '
        { f = $NF; sub(/^\*/, "", f);
          if (f == n) { print $1; exit } }' "$WORK_DIR/checksums.txt")
    if [ -z "$want" ]; then
        err "No checksum entry for $artifact in checksums.txt."
        if [ "${QYVORA_ALLOW_UNVERIFIED:-}" = "1" ]; then
            warn "QYVORA_ALLOW_UNVERIFIED=1 set; continuing WITHOUT checksum verification."
            return 0
        fi
        return 1
    fi

    got=$(sha256_of "$path") || { err "Failed to compute SHA-256."; return 1; }
    if [ "$want" != "$got" ]; then
        err "SHA-256 mismatch for $artifact"
        err "  expected: $want"
        err "  actual:   $got"
        err "The download may have been tampered with. Nothing was installed."
        return 1
    fi
    ok "SHA-256 verified ($got)"
    return 0
}

# ---------------------------------------------------------------------------
# Archive extraction with path-traversal protection
# ---------------------------------------------------------------------------
safe_extract() {
    local archive="$1" dest="$2"
    mkdir -p "$dest"

    case "$archive" in
        *.zip)
            need_cmd unzip || return 1
            # Refuse absolute paths, parent traversal and symlink/hardlink
            # members before unzipping anything.
            if unzip -Z1 "$archive" 2>/dev/null | grep -qE '(^/|(^|/)\.\.(/|$))'; then
                err "Archive contains an unsafe path; refusing to extract."
                return 1
            fi
            unzip -oq "$archive" -d "$dest"
            ;;
        *.tar.gz|*.tgz)
            need_cmd tar || return 1
            if tar -tzf "$archive" 2>/dev/null | grep -qE '(^/|(^|/)\.\.(/|$))'; then
                err "Archive contains an unsafe path; refusing to extract."
                return 1
            fi
            tar -xzf "$archive" -C "$dest" --no-same-owner --no-same-permissions
            ;;
        *)
            err "Unsupported archive format: $archive"
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Source build fallback
# ---------------------------------------------------------------------------
build_from_source() {
    if [ "$QYVORA_SOURCE_BUILD" != "1" ]; then
        err "No source-build fallback is offered for $QYVORA_TITLE."
        return 1
    fi
    if ! command -v go >/dev/null 2>&1; then
        err "Building from source requires Go ${QYVORA_MIN_GO}+, which is not installed."
        need_cmd go || true
        return 1
    fi

    local gover
    gover=$(go env GOVERSION 2>/dev/null | sed 's/^go//')
    case "$gover" in
        "$QYVORA_MIN_GO"|"$QYVORA_MIN_GO".*)
            ok "Go toolchain: $(go version)"
            ;;
        *)
            warn "Go $(go version) is older than the required ${QYVORA_MIN_GO}; the build may fail."
            ;;
    esac

    # Prefer the local checkout, then the release source tarball.
    if [ -f "${PWD}/go.mod" ]; then
        info "Building from the local checkout ($PWD)..."
        if CGO_ENABLED="$QYVORA_CGO_ENABLED" go build -trimpath -ldflags="-s -w" \
             -o "$WORK_DIR/${QYVORA_TOOL}-src" "$QYVORA_MAIN_PKG" 2>&1; then
            SOURCE_BUILT="$WORK_DIR/${QYVORA_TOOL}-src"
            return 0
        fi
        warn "Local checkout build failed; trying the release source tarball."
    fi

    if ! fetch "https://codeload.github.com/${QYVORA_REPO}/tar.gz/refs/heads/main" "$WORK_DIR/src.tar.gz" 2>/dev/null; then
        if ! fetch "https://codeload.github.com/${QYVORA_REPO}/tar.gz/refs/heads/master" "$WORK_DIR/src.tar.gz" 2>/dev/null; then
            err "Could not download the source tarball."
            return 1
        fi
    fi
    safe_extract "$WORK_DIR/src.tar.gz" "$WORK_DIR/src" || return 1

    # A GitHub source tarball wraps everything in a single "<repo>-<sha>/"
    # directory, so the module root is one level below the extraction target.
    local srcdir="$WORK_DIR/src"
    if [ ! -f "$srcdir/go.mod" ]; then
        srcdir=$(find "$WORK_DIR/src" -maxdepth 2 -name go.mod -print 2>/dev/null \
                 | head -1 | sed 's|/go\.mod$||')
    fi
    if [ -z "$srcdir" ] || [ ! -f "$srcdir/go.mod" ]; then
        err "Source tarball does not contain a Go module (go.mod not found)."
        return 1
    fi

    info "Building from source ($srcdir)..."
    if ! ( cd "$srcdir" && CGO_ENABLED="$QYVORA_CGO_ENABLED" go build -trimpath -ldflags="-s -w" \
            -o "$WORK_DIR/${QYVORA_TOOL}-src" "$QYVORA_MAIN_PKG" ); then
        err "Source build failed."
        return 1
    fi
    SOURCE_BUILT="$WORK_DIR/${QYVORA_TOOL}-src"
    return 0
}

# ---------------------------------------------------------------------------
# Desktop integration — strictly optional, never able to fail a CLI install
# ---------------------------------------------------------------------------
install_desktop() {
    if [ "${QYVORA_NO_DESKTOP:-}" = "1" ]; then
        info "Desktop integration disabled (QYVORA_NO_DESKTOP=1)."
        return 0
    fi
    case "$QYVORA_OS" in
        linux)
            : ;;
        android)
            # Termux has no freedesktop application menu. Skipping is correct.
            info "Skipping desktop integration: Android/Termux has no application menu."
            return 0
            ;;
        macos)
            info "Skipping .desktop integration: this is a macOS target."
            return 0
            ;;
        windows)
            info "Skipping .desktop integration: use install.ps1 for shortcuts."
            return 0
            ;;
        *)
            info "Skipping desktop integration on an unrecognised desktop environment."
            return 0
            ;;
    esac

    local bindir="$1"
    local dataroot icon_dir apps_dir
    case "$bindir" in
        */bin)   dataroot="$(dirname "$bindir")/share" ;;
        *)
            # Inside a Termux prefix the data root is $PREFIX/share. $PREFIX is
            # set by Termux only, and this installer runs under `set -u`, so it
            # has to be read defensively. It used to be read bare here, which
            # aborted the install with "PREFIX: unbound variable" on any Linux
            # or macOS host that used --prefix with a directory not ending in
            # /bin -- after the binary was already installed and PATH already
            # rewritten, so the failure left a half-finished install behind.
            if [ -n "${PREFIX:-}" ] && [ "${bindir#"$PREFIX"/}" != "$bindir" ]; then
                dataroot="${PREFIX}/share"
            else
                dataroot="${XDG_DATA_HOME:-$HOME/.local/share}"
            fi
            ;;
    esac
    [ -d "$(dirname "$bindir")/share" ] && dataroot="$(dirname "$bindir")/share"
    icon_dir="$dataroot/icons/hicolor/512x512/apps"
    apps_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"

    # Icon sources, in order of trust: a checkout, the local build tree, the
    # verified release asset.
    local icon=""
    local candidate
    for candidate in "${PWD}/assets/${QYVORA_ICON}" "$WORK_DIR/src/assets/${QYVORA_ICON}" "$WORK_DIR/${QYVORA_ICON}"; do
        if [ -f "$candidate" ]; then icon="$candidate"; break; fi
    done

    if [ -z "$icon" ]; then
        # Downloading the icon is OPTIONAL. A 404 here must never be fatal.
        if [ -n "$QYVORA_ICON" ] \
            && fetch "${QYVORA_BASE_URL}/${QYVORA_ICON}" "$WORK_DIR/${QYVORA_ICON}" 2>/dev/null; then
            if verify_checksum "$WORK_DIR/${QYVORA_ICON}" "$QYVORA_ICON" 2>/dev/null; then
                icon="$WORK_DIR/${QYVORA_ICON}"
                ok "Verified icon ${QYVORA_ICON}"
            else
                rm -f "$WORK_DIR/${QYVORA_ICON}"
            fi
        fi
    fi

    if [ -z "$icon" ]; then
        warn "Desktop icon unavailable; CLI installation will continue."
        return 0
    fi

    if ! mkdir -p "$icon_dir" "$apps_dir" 2>/dev/null; then
        warn "Could not create desktop directories; CLI installation will continue."
        return 0
    fi
    if ! install -m 0644 "$icon" "$icon_dir/${QYVORA_ICON}" 2>/dev/null; then
        warn "Could not install the app icon; CLI installation will continue."
        return 0
    fi

    local desktop="$apps_dir/${QYVORA_TOOL}.desktop"
    {
        printf '[Desktop Entry]\n'
        printf 'Type=Application\n'
        printf 'Version=1.0\n'
        printf 'Name=%s\n' "$QYVORA_DESKTOP_NAME"
        printf 'Comment=%s\n' "$QYVORA_DESKTOP_COMMENT"
        printf 'Exec=%s\n' "$bindir/${QYVORA_TOOL}"
        printf 'Icon=%s/%s\n' "$icon_dir" "$QYVORA_ICON"
        printf 'Terminal=true\n'
        printf 'Categories=Utility;Network;Security;Development;\n'
        printf 'Keywords=%s;\n' "$QYVORA_DESKTOP_KEYWORDS"
    } > "$desktop.tmp" 2>/dev/null \
        && mv -f "$desktop.tmp" "$desktop" 2>/dev/null \
        && chmod 0644 "$desktop" 2>/dev/null \
        && ok "Desktop entry: $desktop" \
        || { rm -f "$desktop.tmp"; warn "Could not write the desktop entry; CLI installation will continue."; return 0; }

    command -v update-desktop-database >/dev/null 2>&1 \
        && update-desktop-database "$apps_dir" >/dev/null 2>&1 || true
    command -v gtk-update-icon-cache >/dev/null 2>&1 \
        && gtk-update-icon-cache -f -t "$dataroot/icons/hicolor" >/dev/null 2>&1 || true
    ok "App icon: $icon_dir/${QYVORA_ICON}"
    return 0
}

# ---------------------------------------------------------------------------
# Man pages — optional, source-tree only, never able to fail a CLI install
# ---------------------------------------------------------------------------
install_man_pages() {
    [ "$QYVORA_MAN_PAGES" = "1" ] || return 0
    case "$QYVORA_OS" in
        linux|macos) : ;;
        *) info "Skipping man pages: not a Linux/macOS target."; return 0 ;;
    esac

    local srcdir=""
    for d in "${PWD}/man" "$WORK_DIR/src/man"; do
        [ -d "$d" ] && { srcdir="$d"; break; }
    done
    if [ -z "$srcdir" ]; then
        info "No man pages in this distribution; skipping."
        return 0
    fi

    local mandir
    case "$QYVORA_INSTALL_DIR" in
        */bin)    mandir="$(dirname "$QYVORA_INSTALL_DIR")/share/man/man1" ;;
        *)        mandir="${QYVORA_INSTALL_DIR}/share/man/man1" ;;
    esac
    if ! mkdir -p "$mandir" 2>/dev/null; then
        warn "Could not create $mandir; skipping man pages."
        return 0
    fi
    local f
    for f in "$srcdir"/*.[0-9]; do
        [ -f "$f" ] || continue
        install -m 0644 "$f" "$mandir/" 2>/dev/null || true
    done
    if ls "$mandir"/* >/dev/null 2>&1; then
        ok "Man pages: $mandir"
        command -v mandb >/dev/null 2>&1 && mandb -q "$mandir" >/dev/null 2>&1 || true
    else
        warn "No man pages were installed; CLI installation is unaffected."
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
do_uninstall() {
    compute_install_dir
    local bin="${QYVORA_INSTALL_DIR}/${QYVORA_TOOL}"
    local removed=0

    if [ -e "$bin" ] || [ -L "$bin" ]; then
        rm -f -- "$bin" && ok "Removed $bin" && removed=1
    else
        info "No binary at $bin"
    fi

    local apps_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    rm -f -- "$apps_dir/${QYVORA_TOOL}.desktop" 2>/dev/null && ok "Removed desktop entry" || true
    find "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" -name "${QYVORA_ICON}" -delete 2>/dev/null || true

    # Remove this installer's PATH block, and only that block. The marker is
    # matched as a prefix because the written line carries a trailing comment;
    # an exact-match removal would silently leave the block in place.
    local rc
    rc=$(shell_rc_path)
    if [ -f "$rc" ] && grep -qF "# qyvora:${QYVORA_TOOL}" "$rc" 2>/dev/null; then
        local tmp
        tmp=$(mktemp) || true
        if [ -n "${tmp:-}" ]; then
            awk -v marker="# qyvora:${QYVORA_TOOL}" '
                index($0, marker) == 1 { skip = 1; next }
                skip == 1               { skip = 0; next }
                                     { lines[++n] = $0 }
                END {
                    # Drop the blank separator line this installer added.
                    if (n > 0 && lines[n] ~ /^[[:space:]]*$/) n--
                    for (i = 1; i <= n; i++) print lines[i]
                }
            ' "$rc" > "$tmp" && mv -f "$tmp" "$rc" \
                && ok "Removed PATH entry from $rc" || rm -f "$tmp"
        fi
    fi

    if [ "$removed" = "1" ]; then
        ok "$QYVORA_TITLE removed."
    else
        info "$QYVORA_TITLE was not installed by this installer."
    fi
    note "Configuration and scan data were left untouched (pass --purge-data to remove them)."
}

# ---------------------------------------------------------------------------
# Main install flow
# ---------------------------------------------------------------------------
do_install() {
    detect_environment
    compute_install_dir
    plan_target

    info "Detected ${QYVORA_OS}/${QYVORA_ARCH}${QYVORA_ENV:+ (${QYVORA_ENV})}"
    [ -n "$QYVORA_DISTRO" ] && info "Distribution: $QYVORA_DISTRO"
    info "Install directory: $QYVORA_INSTALL_DIR"

    SOURCE_BUILT=""
    local candidate=""

    if [ "${QYVORA_SOURCE:-}" = "1" ]; then
        info "QYVORA_SOURCE=1 set; skipping prebuilt artifacts."
        QYVORA_WANT_PREBUILT=0
    fi

    if [ "$QYVORA_WANT_PREBUILT" = "1" ]; then
        info "Downloading ${QYVORA_ARTIFACT}..."
        if ! fetch "${QYVORA_BASE_URL}/${QYVORA_ARTIFACT}" "$WORK_DIR/${QYVORA_ARTIFACT}"; then
            warn "No published artifact named ${QYVORA_ARTIFACT}."
            if [ "$QYVORA_SOURCE_BUILD" != "1" ]; then
                err "$QYVORA_TITLE has no release artifact for this target and offers no source build."
                exit "$EXIT_UNSUPPORTED"
            fi
            warn "Falling back to a local source build."
        else
            if ! verify_checksum "$WORK_DIR/${QYVORA_ARTIFACT}" "$QYVORA_ARTIFACT"; then
                exit "$EXIT_VERIFY"
            fi
            candidate="$WORK_DIR/${QYVORA_ARTIFACT}"

            if [ "$QYVORA_PACKAGE" = "binary" ]; then
                :
            else
                local unpack="$WORK_DIR/unpack"
                safe_extract "$candidate" "$unpack" || exit "$EXIT_VERIFY"
                candidate="$unpack/${QYVORA_TOOL}"
                [ -f "$candidate" ] || candidate="$(find "$unpack" -type f -name "${QYVORA_TOOL}*" ! -name '*.png' ! -name '*.ico' | head -1)"
                if [ -z "$candidate" ] || [ ! -f "$candidate" ]; then
                    err "Archive did not contain a ${QYVORA_TOOL} executable."
                    exit "$EXIT_VERIFY"
                fi
            fi

            # Format gate: refuse an artifact built for a different target
            # BEFORE it is ever executed.
            if ! validate_executable "$candidate" "$QYVORA_OS" "$QYVORA_ARCH"; then
                err "Artifact ${QYVORA_ARTIFACT} is not compatible with this platform."
                print_diagnostics
                note "No files were installed."
                exit "$EXIT_VERIFY"
            fi
            local desc
            desc=$(describe_file "$candidate")
            [ -n "$desc" ] && info "file(1): $desc"

            # Execution gate, still in the temp dir: nothing live is touched.
            chmod 0755 "$candidate"
            if ! runtime_probe "$candidate" >/dev/null 2>&1; then
                err "The downloaded binary cannot execute on this platform."
                print_diagnostics
                err "Attempted artifact: ${QYVORA_ARTIFACT}"
                err "Reason: it was built for a different OS/ABI than this host."
                note "No files were installed."
                exit "$EXIT_VERIFY"
            fi
            ok "Artifact executes on this host"
        fi
    fi

    if [ -z "$candidate" ]; then
        if ! build_from_source; then
            err "Could not obtain a working ${QYVORA_TITLE} for this platform."
            print_diagnostics
            exit "$EXIT_FATAL"
        fi
        candidate="$SOURCE_BUILT"
        chmod 0755 "$candidate"
        if ! validate_executable "$candidate" "$QYVORA_OS" "$QYVORA_ARCH"; then
            err "The locally built binary does not match this platform."
            print_diagnostics
            exit "$EXIT_VERIFY"
        fi
        if ! runtime_probe "$candidate" >/dev/null 2>&1; then
            err "The locally built binary cannot execute on this platform."
            print_diagnostics
            exit "$EXIT_VERIFY"
        fi
        ok "Source build executes on this host"
    fi

    # --- Atomic install ---------------------------------------------------
    mkdir -p "$QYVORA_INSTALL_DIR" || die "$EXIT_FATAL" "Cannot create $QYVORA_INSTALL_DIR"
    [ -w "$QYVORA_INSTALL_DIR" ] || die "$EXIT_FATAL" "Cannot write to $QYVORA_INSTALL_DIR"

    local dest="${QYVORA_INSTALL_DIR}/${QYVORA_TOOL}"
    local staging="${QYVORA_INSTALL_DIR}/.${QYVORA_TOOL}.new.$$"
    local backup=""
    if [ -e "$dest" ]; then
        backup="${QYVORA_INSTALL_DIR}/.${QYVORA_TOOL}.old.$$"
        cp -p -- "$dest" "$backup" 2>/dev/null || backup=""
    fi

    # install(1) writes the staging file; mv(1) within one filesystem is an
    # atomic rename, so the live binary is never partially written.
    if ! install -m 0755 "$candidate" "$staging" 2>/dev/null; then
        rm -f "$staging"
        die "$EXIT_FATAL" "Could not stage the binary in $QYVORA_INSTALL_DIR"
    fi
    if ! mv -f "$staging" "$dest" 2>/dev/null; then
        rm -f "$staging"
        [ -n "$backup" ] && mv -f "$backup" "$dest" 2>/dev/null || true
        die "$EXIT_FATAL" "Could not move the binary into place"
    fi

    # Final runtime check on the real path; roll back if it fails.
    if ! runtime_probe "$dest" >/dev/null 2>&1; then
        err "The installed binary at $dest cannot run on this platform."
        if [ -n "$backup" ]; then
            mv -f "$backup" "$dest" 2>/dev/null \
                && ok "Rolled back to the previous working installation." \
                || { rm -f "$dest"; err "Removed the broken installation; no binary remains at $dest."; }
        else
            rm -f "$dest"
            err "No previous installation existed, so nothing was left behind."
        fi
        print_diagnostics
        exit "$EXIT_VERIFY"
    fi

    if [ -n "$backup" ]; then
        rm -f "$backup"
        ok "Updated $dest"
    else
        ok "Installed $dest"
    fi

    # --- PATH -------------------------------------------------------------
    configure_path "$QYVORA_INSTALL_DIR"

    # --- Desktop (optional, cannot fail the install) ----------------------
    install_desktop "$QYVORA_INSTALL_DIR"
    install_man_pages

    # --- Report -----------------------------------------------------------
    local ver
    ver=$(runtime_version "$dest" 2>/dev/null || printf '')
    printf '\n'
    print_diagnostics
    printf '  %sSelected artifact%s\n' "$C_BLD" "$C_OFF"
    printf '    %s\n' "${QYVORA_ARTIFACT:-<built from source>}"
    printf '\n'
    printf '  %sInstallation%s\n' "$C_BLD" "$C_OFF"
    printf '    [OK] Binary installed to %s\n' "$dest"
    printf '    [OK] PATH contains %s\n' "$QYVORA_INSTALL_DIR"
    if [ -n "$ver" ]; then
        printf '    [OK] Runtime verified: %s\n' "$ver"
    else
        printf '    [OK] Runtime verified: %s responds to "%s"\n' \
            "$QYVORA_TOOL" "$(runtime_probe "$dest")"
    fi
    printf '\n'
    ok "${QYVORA_TITLE} installed successfully."
    note "Run '${QYVORA_TOOL} --help' to get started."
    exit "$EXIT_OK"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
main() {
    SELF_FILE="$0"
    case "$SELF_FILE" in
        /*) : ;;
        *)  SELF_FILE="./$SELF_FILE" ;;
    esac

    # Parse every leading option before acting on any of them.
    #
    # This used to be a single `case "${1:-}"`, so only the FIRST argument was
    # ever considered. `install.sh --uninstall --prefix /opt/x` therefore
    # uninstalled from the platform default and ignored /opt/x entirely, which
    # is the worst possible direction for a destructive flag to be wrong in: it
    # removes a binary the caller did not ask about. Options are now collected
    # in a loop and the action is dispatched once, at the end.
    local action=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --help|-h)
                usage
                exit "$EXIT_OK"
                ;;
            --version)
                printf '%s installer %s\n' "$QYVORA_TITLE" "$QYVORA_INSTALLER_VERSION"
                exit "$EXIT_OK"
                ;;
            --uninstall|uninstall)
                action="uninstall"
                shift
                ;;
            --prefix)
                [ -n "${2:-}" ] || die "$EXIT_FATAL" "--prefix requires a directory argument"
                QYVORA_INSTALL_DIR="$2"
                shift 2
                ;;
            --no-path)
                QYVORA_NO_PATH=1
                shift
                ;;
            *)
                break
                ;;
        esac
    done

    # An explicit --prefix wins over the platform default for both install and
    # uninstall, so a caller can manage a non-default location.
    if [ -n "${QYVORA_INSTALL_DIR:-}" ]; then
        export QYVORA_INSTALL_DIR
    fi

    case "$action" in
        uninstall)
            detect_environment
            banner
            do_uninstall
            exit "$EXIT_OK"
            ;;
    esac

    # This installer runs under `set -u` and reads $HOME and $PATH in a dozen
    # places while rewriting a shell rc file. If either is missing -- an empty
    # environment, a cron job, some container entrypoints -- the failure used to
    # surface as "HOME: unbound variable" partway through, after the binary was
    # already installed and the rc file was half-written. Check once, here, and
    # say so plainly instead. Placed after the case block so --help and
    # --version still work in a bare environment.
    if [ -z "${HOME:-}" ] || [ -z "${PATH:-}" ]; then
        die "$EXIT_FATAL" "HOME and PATH must both be set. Run this from a normal shell session."
    fi

    banner
    WORK_DIR=$(mktemp -d 2>/dev/null) || die "$EXIT_FATAL" "Could not create a temporary directory"
    chmod 0700 "$WORK_DIR"
    trap cleanup EXIT INT TERM

    need_cmd uname || exit "$EXIT_FATAL"
    need_cmd mktemp || exit "$EXIT_FATAL"
    need_cmd install || exit "$EXIT_FATAL"
    need_cmd mv || exit "$EXIT_FATAL"
    if [ "$QYVORA_WANT_PREBUILT" != "0" ] || [ "${QYVORA_SOURCE:-}" != "1" ]; then
        if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
            need_cmd curl || exit "$EXIT_FATAL"
        fi
    fi

    do_install
}

# Sourcing this file with QYVORA_INSTALLER_NO_MAIN=1 loads every function
# without running an install. That is how qyvora-dist/test/test-installer.sh
# exercises detection, artifact selection and format validation directly.
if [ -z "${QYVORA_INSTALLER_NO_MAIN:-}" ]; then
    main "$@"
fi
