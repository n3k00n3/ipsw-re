#!/usr/bin/env bash
# ipsw-detect.sh — Static protection detector for iOS binaries
# Usage:
#   ./ipsw-detect.sh <binary>
#   ./ipsw-detect.sh <binary> --wordlist /path/to/custom.txt
#   ./ipsw-detect.sh <binary> --swift-only
#   ./ipsw-detect.sh <binary> --objc-only

# ── Colors ────────────────────────────────────────────────────────────────────
R='\033[0m'
BOLD='\033[1m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
GREEN='\033[1;32m'
MAGENTA='\033[1;35m'
BLUE='\033[1;34m'
DIM='\033[2m'
DIM_YELLOW='\033[2;33m'
DIM_RED='\033[2;31m'
WHITE='\033[0;37m'

# ── Known suspicious frameworks (name → description) ─────────────────────────
# Format: "framework_substring|Category|Description"
KNOWN_FRAMEWORKS=(
    # ── Jailbreak detection ──
    "IOSSecuritySuite|Jailbreak / Anti-Tamper|Comprehensive security suite: jailbreak, debugger, Frida, emulator detection"
    "DTTJailbreakDetection|Jailbreak Detection|Lightweight jailbreak detection library"
    "jailbreak_root_detection|Jailbreak Detection|Flutter plugin — jailbreak/root detection"
    "safe_device|Jailbreak Detection|Flutter safe_device plugin — jailbreak and developer mode checks"
    "TrustKit|SSL Pinning|SSL/TLS certificate pinning via TrustKit"
    "AlamoFireSSL|SSL Pinning|Alamofire with SSL pinning"
    "SSLPinning|SSL Pinning|Generic SSL pinning framework"
    "CertificatePinning|SSL Pinning|Certificate pinning library"
    # ── Secure storage ──
    "flutter_secure_storage|Secure Storage|Flutter secure storage — Keychain-backed encrypted storage"
    "KeychainAccess|Secure Storage|Swift Keychain wrapper"
    "SAMKeychain|Secure Storage|Objective-C Keychain helper"
    "UICKeyChainStore|Secure Storage|Keychain abstraction layer"
    # ── Biometrics / auth ──
    "local_auth_darwin|Biometric Auth|Flutter local_auth — Face ID / Touch ID"
    "LocalAuthentication|Biometric Auth|Apple LocalAuthentication framework"
    # ── Obfuscation / integrity ──
    "iXGuard|Obfuscation / Integrity|iXGuard — code obfuscation and RASP protection"
    "Guardsquare|Obfuscation / Integrity|Guardsquare DexGuard/iXGuard RASP"
    "AppSealing|Obfuscation / Integrity|AppSealing — in-app protection and obfuscation"
    "Arxan|Obfuscation / Integrity|Arxan application protection"
    "promon|Obfuscation / Integrity|Promon SHIELD in-app protection"
    # ── Crash / telemetry (also used for tamper detection) ──
    "FirebaseCrashlytics|Crash Reporting|Firebase Crashlytics — crash and ANR reporting"
    "Sentry|Crash Reporting|Sentry SDK — error and performance monitoring"
    "Bugsnag|Crash Reporting|Bugsnag crash reporting"
    # ── Flutter security plugins ──
    "flutter_udid|Device Fingerprint|Flutter UDID — unique device identifier"
    "device_info_plus|Device Fingerprint|Flutter device_info_plus — hardware/OS info"
    # ── Root/device checks ──
    "RootBeer|Root Detection|RootBeer — Android-style root detection (cross-platform)"
)

# ── Defaults ──────────────────────────────────────────────────────────────────
BINARY=""
WORDLIST="$(dirname "$0")/protections.txt"
MODE="both"

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --wordlist)   WORDLIST="$2"; shift 2 ;;
        --swift-only) MODE="swift"; shift ;;
        --objc-only)  MODE="objc"; shift ;;
        *)            BINARY="$1"; shift ;;
    esac
done

if [[ -z "$BINARY" ]]; then
    printf "Usage: %s <binary> [--wordlist <file>] [--swift-only|--objc-only]\n" "$0"
    exit 1
fi

if [[ ! -f "$WORDLIST" ]]; then
    printf "Wordlist not found: %s\n" "$WORDLIST"
    exit 1
fi

# ── Load wordlist ─────────────────────────────────────────────────────────────
PATTERNS=()
while IFS= read -r pat; do
    [[ "$pat" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${pat// }" ]] && continue
    PATTERNS+=("$pat")
done < "$WORDLIST"

if [[ ${#PATTERNS[@]} -eq 0 ]]; then
    printf "No patterns loaded from wordlist.\n"
    exit 1
fi

# Build grep pattern via explicit loop (bash 3 compat)
GREP_PATTERN=""
for _p in "${PATTERNS[@]}"; do
    if [[ -z "$GREP_PATTERN" ]]; then
        GREP_PATTERN="$_p"
    else
        GREP_PATTERN="${GREP_PATTERN}|${_p}"
    fi
done

# ── Temp files ────────────────────────────────────────────────────────────────
WORK_DIR=$(mktemp -d)
CLASSES_FILE="$WORK_DIR/classes.txt"
METHODS_FILE="$WORK_DIR/methods.txt"
DYLIBS_FILE="$WORK_DIR/dylibs.txt"
touch "$CLASSES_FILE" "$METHODS_FILE" "$DYLIBS_FILE"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# ── Section 0: Linked frameworks scan ────────────────────────────────────────
scan_dylibs() {
    # Extract all LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB lines
    local dylib_output
    dylib_output=$(ipsw macho info "$BINARY" 2>/dev/null \
        | grep -E 'LC_LOAD_(WEAK_)?DYLIB' \
        | sed 's/.*LC_LOAD_\(WEAK_\)\?DYLIB[[:space:]]*//')

    while IFS= read -r dylib_path; do
        [[ -z "$dylib_path" ]] && continue
        # Extract just the framework/dylib name from the path
        local name
        name=$(basename "$dylib_path" | sed 's/\.framework.*//' | sed 's/\.dylib.*//')

        for entry in "${KNOWN_FRAMEWORKS[@]}"; do
            local pattern category description
            pattern=$(echo "$entry" | cut -d'|' -f1)
            category=$(echo "$entry" | cut -d'|' -f2)
            description=$(echo "$entry" | cut -d'|' -f3)

            # Case-insensitive substring match
            local name_lower pattern_lower
            name_lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')
            pattern_lower=$(echo "$pattern" | tr '[:upper:]' '[:lower:]')

            if [[ "$name_lower" == *"$pattern_lower"* ]]; then
                printf '%s\t%s\t%s\t%s\n' "$name" "$dylib_path" "$category" "$description" >> "$DYLIBS_FILE"
                break
            fi
        done
    done <<< "$dylib_output"
}

# ── Symbol parser ─────────────────────────────────────────────────────────────
parse_output() {
    local source="$1"
    local current_type=""

    while IFS= read -r line; do

        if [[ "$line" =~ ^(class|struct|enum|protocol|extension)[[:space:]] ]]; then
            current_type="$line"
            if echo "$line" | grep -qiE "$GREP_PATTERN"; then
                local matched
                matched=$(echo "$line" | grep -oiE "$GREP_PATTERN" | sort -u | tr '\n' ' ')
                printf '%s\t%s\t%s\n' "$source" "$line" "$matched" >> "$CLASSES_FILE"
            fi
            continue
        fi

        local is_member=0
        if [[ "$line" =~ ^[[:space:]]+(func|let|var|case)[[:space:]] ]] \
        || [[ "$line" =~ ^[[:space:]]*(static|class)[[:space:]]+func[[:space:]] ]] \
        || [[ "$line" =~ ^[[:space:]]*[-+]\[ ]]; then
            is_member=1
        fi

        if [[ $is_member -eq 1 ]]; then
            if echo "$line" | grep -qiE "$GREP_PATTERN"; then
                local matched
                matched=$(echo "$line" | grep -oiE "$GREP_PATTERN" | sort -u | tr '\n' ' ')
                local parent="[$source] ${current_type:-<global>}"
                printf '%s\t%s\t%s\n' "$parent" "$line" "$matched" >> "$METHODS_FILE"
            fi
        fi

    done
}

# ── Run scans ─────────────────────────────────────────────────────────────────
printf "${DIM}  Scanning %s ...${R}\n" "$BINARY"

scan_dylibs

if [[ "$MODE" == "both" || "$MODE" == "swift" ]]; then
    ipsw macho info "$BINARY" --swift 2>/dev/null | parse_output "Swift"
fi
if [[ "$MODE" == "both" || "$MODE" == "objc" ]]; then
    ipsw macho info "$BINARY" --objc  2>/dev/null | parse_output "ObjC"
fi

# ── Count results (awk avoids grep -c newline issues on macOS bash 3) ─────────
count_lines() { awk 'END{print NR}' "$1" 2>/dev/null || echo 0; }

n_dylibs=$(count_lines "$DYLIBS_FILE")
n_classes=$(count_lines "$CLASSES_FILE")
n_methods=$(count_lines "$METHODS_FILE")

n_parents=0
if [[ "$n_methods" -gt 0 ]]; then
    n_parents=$(cut -f1 "$METHODS_FILE" | sort -u | awk 'END{print NR}')
fi

total=$(( n_dylibs + n_classes + n_methods ))

# ── Report header ─────────────────────────────────────────────────────────────
printf "\n"
printf "${BOLD}╔══════════════════════════════════════════════════════╗${R}\n"
printf "${BOLD}║         PROTECTION DETECTION REPORT                  ║${R}\n"
printf "${BOLD}╚══════════════════════════════════════════════════════╝${R}\n"
printf "${DIM}  Binary  : %s${R}\n"   "$BINARY"
printf "${DIM}  Wordlist: %s (%d patterns)${R}\n" "$WORDLIST" "${#PATTERNS[@]}"
printf "\n"

if [[ $total -eq 0 ]]; then
    printf "${GREEN}  ✓ No protection patterns detected.${R}\n\n"
    exit 0
fi

# ── Section 0: Suspicious linked frameworks ───────────────────────────────────
if [[ $n_dylibs -gt 0 ]]; then
    printf "${MAGENTA}${BOLD}▶ SUSPICIOUS LINKED FRAMEWORKS  (%d found)${R}\n\n" "$n_dylibs"

    current_cat=""
    # Sort by category (field 3) for grouped output
    sort -t$'\t' -k3 "$DYLIBS_FILE" | while IFS=$'\t' read -r name path category description; do
        if [[ "$category" != "$current_cat" ]]; then
            [[ -n "$current_cat" ]] && printf "\n"
            printf "  ${BOLD}${CYAN}[%s]${R}\n" "$category"
            current_cat="$category"
        fi
        printf "  ${BOLD}${WHITE}%-40s${R}  ${DIM}%s${R}\n" "$name" "$path"
        printf "  ${DIM_YELLOW}  ↳ %s${R}\n" "$description"
    done
    printf "\n"
fi

# ── Section 1: Suspicious type declarations ───────────────────────────────────
if [[ $n_classes -gt 0 ]]; then
    printf "${RED}${BOLD}▶ SUSPICIOUS TYPE DECLARATIONS  (%d found)${R}\n\n" "$n_classes"

    while IFS=$'\t' read -r source decl matched; do
        if   [[ "$decl" =~ ^class[[:space:]] ]];    then color="$CYAN$BOLD"
        elif [[ "$decl" =~ ^struct[[:space:]] ]];   then color="$YELLOW$BOLD"
        elif [[ "$decl" =~ ^enum[[:space:]] ]];     then color="$MAGENTA$BOLD"
        elif [[ "$decl" =~ ^protocol[[:space:]] ]]; then color="$BLUE$BOLD"
        else color="$BOLD"; fi

        printf "  ${DIM}[%s]${R} ${color}%s${R}\n" "$source" "$decl"
        printf "  ${DIM_RED}  ↳ matched: %s${R}\n\n" "$matched"
    done < "$CLASSES_FILE"
fi

# ── Section 2: Suspicious methods grouped by parent type ──────────────────────
if [[ $n_methods -gt 0 ]]; then
    printf "${YELLOW}${BOLD}▶ SUSPICIOUS METHODS / FIELDS  (%d types affected)${R}\n\n" "$n_parents"

    current_parent=""
    while IFS=$'\t' read -r parent mline matched; do
        if [[ "$parent" != "$current_parent" ]]; then
            [[ -n "$current_parent" ]] && printf "\n"
            printf "  ${BOLD}%s${R}\n" "$parent"
            current_parent="$parent"
        fi

        if   [[ "$mline" =~ ^[[:space:]]*(static|class)[[:space:]]+func ]]; then lcolor="$GREEN$BOLD"
        elif [[ "$mline" =~ ^[[:space:]]*func ]];                            then lcolor="$GREEN"
        elif [[ "$mline" =~ ^[[:space:]]*(let|var) ]];                       then lcolor='\033[0;96m'
        elif [[ "$mline" =~ ^[[:space:]]*[-+]\[ ]];                          then lcolor="$GREEN"
        else lcolor="$R"; fi

        printf "    ${lcolor}%s${R}\n" "$mline"
        printf "    ${DIM_YELLOW}↳ matched: %s${R}\n" "$matched"
    done < "$METHODS_FILE"
    printf "\n"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf "${BOLD}──────────────────────────────────────────────────────${R}\n"
printf "  ${BOLD}Summary${R}\n"
printf "  Suspicious linked frameworks : ${MAGENTA}${BOLD}%d${R}\n" "$n_dylibs"
printf "  Suspicious type declarations : ${RED}${BOLD}%d${R}\n"     "$n_classes"
printf "  Types with suspicious members: ${YELLOW}${BOLD}%d${R}\n"  "$n_parents"
printf "  Total suspicious members     : ${YELLOW}${BOLD}%d${R}\n"  "$n_methods"
printf "${BOLD}──────────────────────────────────────────────────────${R}\n\n"