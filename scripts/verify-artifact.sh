#!/usr/bin/env bash
#
# SHAKA release artifact verifier
#
# GENERATED from qyvora-dist/verify-artifact.template.sh — do not edit by hand.
# Change the template + qyvora-dist/tools.def, then run qyvora-dist/generate.sh.
#
# This is the release gate. It refuses to pass an artifact that is named for one
# target but actually contains a binary for another, which is the class of bug
# that shipped ANANSI's ELF ET_EXEC to Android and made the Termux install fail
# with "unexpected e_type: 2".
#
# Usage:
#   scripts/verify-artifact.sh <file> <goos> <goarch>
#
#   <goos>    one of: linux macos windows android
#   <goarch>  one of: amd64 arm64
#
# Rules enforced:
#   * ELF magic for linux/macos/android, PE/MZ magic for windows, Mach-O for
#     macos. A file whose header does not match its name is rejected.
#   * e_machine must match the requested architecture, so a mislabelled
#     linux/arm64 can never be published as linux/amd64.
#   * ELF 32/64-bit class must match the requested architecture.
#   * android/arm64 must be ET_DYN (PIE). Android's bionic linker64 refuses
#     ET_EXEC outright, so a GOOS=linux build shipped to Termux can never be
#     published as an Android artifact.
#   * nothing else is assumed: no network, no toolchain, no $HOME.

set -euo pipefail

PROG="${0##*/}"
C_OK=''; C_ERR=''; C_OFF=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_OK=$(printf '\033[32m'); C_ERR=$(printf '\033[31m'); C_OFF=$(printf '\033[0m')
fi

die()  { printf '%s%s: %s%s\n' "$C_ERR" "$PROG" "$1" "$C_OFF" >&2; exit 1; }
ok()   { printf '  %sOK%s   %s\n' "$C_OK" "$C_OFF" "$1"; }

[ "$#" -eq 3 ] || die "usage: $PROG <file> <goos> <goarch>"

FILE="$1"
WANT_OS="$2"
WANT_ARCH="$3"

[ -f "$FILE" ] || die "no such file: $FILE"
[ -s "$FILE" ] || die "empty file: $FILE"

# ---------------------------------------------------------------------------
# Byte readers. `od` is in coreutils and busybox, so this works on a bare
# runner, inside Termux, and on macOS, unlike `xxd`.
# ---------------------------------------------------------------------------
# Byte at an offset, unsigned decimal.
byte_at() {
    od -An -tu1 -j"$2" -N1 "$1" 2>/dev/null | tr -d ' \n'
}
# 16-bit little-endian word at an offset, unsigned decimal.
le16_at() {
    local lo hi
    lo=$(byte_at "$1" "$2")
    hi=$(byte_at "$1" $(( $2 + 1 )))
    [ -n "$lo" ] && [ -n "$hi" ] || return 1
    printf '%s' $(( lo + (hi << 8) ))
}

# ---------------------------------------------------------------------------
# Expected machine code and ELF class per architecture.
# ---------------------------------------------------------------------------
want_machine=''
want_class=''
case "$WANT_ARCH" in
    amd64) want_machine=62;  want_class=2 ;;   # EM_X86_64, ELFCLASS64
    arm64) want_machine=183; want_class=2 ;;   # EM_AARCH64, ELFCLASS64
    armv7) want_machine=40;  want_class=1 ;;   # EM_ARM, ELFCLASS32
    *) die "unsupported architecture '$WANT_ARCH' (expected amd64 or arm64)" ;;
esac

case "$WANT_OS" in
    linux|macos|android|windows) : ;;
    *) die "unsupported target OS '$WANT_OS' (expected linux, macos, windows or android)" ;;
esac

printf '%s%s: %s/%s%s\n' "$C_OK" "$FILE" "$WANT_OS" "$WANT_ARCH" "$C_OFF"

# ---------------------------------------------------------------------------
# Windows: PE. We only gate the container format here; the PE optional header
# machine word is checked too, because a renamed .exe is the same bug class.
# ---------------------------------------------------------------------------
if [ "$WANT_OS" = "windows" ]; then
    m0=$(byte_at "$FILE" 0); m1=$(byte_at "$FILE" 1)
    if [ "$m0" != "77" ] || [ "$m1" != "90" ]; then
        die "not a PE executable: expected MZ magic, got $(printf '%s %s' "${m0:-?}" "${m1:-?}")"
    fi
    ok "PE (MZ) container"
    # e_lfanew at offset 0x3c, then 'PE\0\0' at that offset.
    lfanew=$(le16_at "$FILE" 60)
    if [ -z "$lfanew" ] || [ "$lfanew" -lt 1 ] 2>/dev/null; then
        die "PE header offset (e_lfanew) is unreadable"
    fi
    p0=$(byte_at "$FILE" "$lfanew")
    p1=$(byte_at "$FILE" $(( lfanew + 1 )))
    if [ "$p0" != "80" ] || [ "$p1" != "69" ]; then
        die "PE signature not found at e_lfanew=$lfanew"
    fi
    ok "PE signature present"
    # Machine word sits 4 bytes past the PE signature.
    pe_machine=$(le16_at "$FILE" $(( lfanew + 4 )))
    case "$WANT_ARCH" in
        amd64) want_pe=$(( 0x8664 )) ;;   # IMAGE_FILE_MACHINE_AMD64
        arm64) want_pe=$(( 0xAA64 )) ;;   # IMAGE_FILE_MACHINE_ARM64
    esac
    if [ "$pe_machine" != "$want_pe" ]; then
        die "PE machine mismatch: artifact is machine=$pe_machine, $WANT_OS/$WANT_ARCH needs machine=$want_pe"
    fi
    ok "PE machine matches $WANT_ARCH"
    exit 0
fi

# ---------------------------------------------------------------------------
# Mach-O: macOS. Magic is endian-specific, so check both byte orders.
# ---------------------------------------------------------------------------
if [ "$WANT_OS" = "macos" ]; then
    m0=$(byte_at "$FILE" 0); m1=$(byte_at "$FILE" 1); m2=$(byte_at "$FILE" 2); m3=$(byte_at "$FILE" 3)
    # Mach-O magics as they appear on disk, in decimal (od -tu1 output):
    #   206 250 237 254  MH_MAGIE    32-bit, little-endian
    #   207 250 237 254  MH_MAGIC_64 64-bit, little-endian
    #   254 237 250 206  MH_CIGAM    32-bit, big-endian
    #   254 237 250 207  MH_CIGAM_64 64-bit, big-endian
    #   202 190 186 190  FAT_MAGIC   universal binary
    case "$m0 $m1 $m2 $m3" in
        '206 250 237 254'|'207 250 237 254'|'254 237 250 206'|'254 237 250 207'|'202 190 186 190')
            ok "Mach-O container" ;;
        *)
            die "not a Mach-O executable: magic was $(printf '%s %s %s %s' "${m0:-?}" "${m1:-?}" "${m2:-?}" "${m3:-?}")"
            ;;
    esac
    # cputype is a 32-bit field at offset 4; assemble it from two 16-bit reads
    # because le16_at is the only endian-aware helper here.
    cpu_lo=$(le16_at "$FILE" 4)
    cpu_hi=$(le16_at "$FILE" 6)
    cpu=$(( cpu_lo + (cpu_hi << 16) ))
    case "$WANT_ARCH" in
        amd64) want_cpu=$(( 0x01000007 )) ;;   # CPU_TYPE_X86_64
        arm64) want_cpu=$(( 0x0100000C )) ;;   # CPU_TYPE_ARM64
    esac
    if [ "$cpu" != "$want_cpu" ]; then
        die "Mach-O cputype mismatch: artifact is cputype=$cpu, $WANT_OS/$WANT_ARCH needs cputype=$want_cpu"
    fi
    ok "Mach-O cputype matches $WANT_ARCH"
    exit 0
fi

# ---------------------------------------------------------------------------
# ELF: linux and android.
# ---------------------------------------------------------------------------
m0=$(byte_at "$FILE" 0); m1=$(byte_at "$FILE" 1); m2=$(byte_at "$FILE" 2); m3=$(byte_at "$FILE" 3)
if [ "$m0" != "127" ] || [ "$m1" != "69" ] || [ "$m2" != "76" ] || [ "$m3" != "70" ]; then
    die "not an ELF executable: expected \\x7fELF, got $(printf '%s %s %s %s' "${m0:-?}" "${m1:-?}" "${m2:-?}" "${m3:-?}")"
fi
ok "ELF container"

class=$(byte_at "$FILE" 4)
data=$(byte_at "$FILE" 5)
if [ "$data" != "1" ]; then
    die "ELF is big-endian (EI_DATA=$data); every QYVORA target is little-endian"
fi
if [ "$class" != "$want_class" ]; then
    die "ELF class mismatch: artifact is ELFCLASS$( [ "$class" = 1 ] && echo 32 || echo 64 ), $WANT_OS/$WANT_ARCH needs ELFCLASS$( [ "$want_class" = 1 ] && echo 32 || echo 64 )"
fi
ok "ELF class matches $WANT_ARCH ($( [ "$class" = 1 ] && echo 32 || echo 64 )-bit)"

emachine=$(le16_at "$FILE" 18)
if [ "$emachine" != "$want_machine" ]; then
    die "ELF machine mismatch: artifact is e_machine=$emachine, $WANT_OS/$WANT_ARCH needs e_machine=$want_machine"
fi
ok "ELF e_machine matches $WANT_ARCH"

etype=$(le16_at "$FILE" 16)
case "$etype" in
    2) etype_name='ET_EXEC' ;;
    3) etype_name='ET_DYN' ;;
    *) etype_name="type $etype" ;;
esac

# The check that would have caught the original Termux failure.
if [ "$WANT_OS" = "android" ]; then
    if [ "$etype" != "3" ]; then
        die "Android artifact is $etype_name, but Android's bionic linker64 only loads position-independent executables (ET_DYN). A GOOS=linux build is ET_EXEC and is rejected on device with 'unexpected e_type: 2'. Build this target with GOOS=android."
    fi
    ok "Android artifact is ET_DYN (PIE) as bionic requires"
else
    # A GOOS=android build is a legitimate PIE ELF and is fine elsewhere, so
    # both types pass on linux; just report which one this is.
    ok "ELF type is $etype_name"
fi

printf '  %sPASS%s %s is a valid %s/%s artifact\n' "$C_OK" "$C_OFF" "$FILE" "$WANT_OS" "$WANT_ARCH"
exit 0
