#!/usr/bin/env bash
# binary-shield.sh — iOS binary protection checker
# Shows active protections, missing ones, and their severity
# Usage:
#   ./binary-shield.sh <binary>
#   ./binary-shield.sh <path/to/App.app>
#   ./binary-shield.sh <binary> --ent-only
#   ./binary-shield.sh <binary> --macho-only

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
DIM_GREEN='\033[2;32m'
WHITE='\033[0;37m'

# ── Arg parsing ───────────────────────────────────────────────────────────────
BINARY=""
MODE="both"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ent-only)   MODE="ent";   shift ;;
        --macho-only) MODE="macho"; shift ;;
        *)            BINARY="$1";  shift ;;
    esac
done

if [[ -z "$BINARY" ]]; then
    printf "Usage: %s <binary|App.app> [--ent-only|--macho-only]\n" "$0"
    exit 1
fi

# Auto-find binary inside .app bundle
if [[ -d "$BINARY" ]]; then
    APP_DIR="$BINARY"
    EXEC_NAME=$(defaults read "$APP_DIR/Info.plist" CFBundleExecutable 2>/dev/null)
    if [[ -z "$EXEC_NAME" ]]; then
        EXEC_NAME=$(basename "$APP_DIR" .app)
    fi
    BINARY="$APP_DIR/$EXEC_NAME"
fi

if [[ ! -f "$BINARY" ]]; then
    printf "Binary not found: %s\n" "$BINARY"
    exit 1
fi

# ── Counters ──────────────────────────────────────────────────────────────────
n_present=0
n_missing_critical=0
n_missing_warn=0

mark_present()          { n_present=$(( n_present + 1 )); }
mark_missing_critical() { n_missing_critical=$(( n_missing_critical + 1 )); }
mark_missing_warn()     { n_missing_warn=$(( n_missing_warn + 1 )); }

# ── Helpers ───────────────────────────────────────────────────────────────────
check() {
    local label="$1"
    local status="$2"   # "present" | "missing_critical" | "missing_warn"
    local detail="$3"

    case "$status" in
        present)
            printf "  ${GREEN}${BOLD}[✓] %-45s${R} ${DIM_GREEN}%s${R}\n" "$label" "$detail"
            mark_present
            ;;
        missing_critical)
            printf "  ${RED}${BOLD}[✗] %-45s${R} ${DIM_RED}%s${R}\n" "$label" "$detail"
            mark_missing_critical
            ;;
        missing_warn)
            printf "  ${YELLOW}${BOLD}[⚠] %-45s${R} ${DIM_YELLOW}%s${R}\n" "$label" "$detail"
            mark_missing_warn
            ;;
        info)
            printf "  ${CYAN}${BOLD}[i] %-45s${R} ${DIM}%s${R}\n" "$label" "$detail"
            ;;
    esac
}

# ── Get entitlements ──────────────────────────────────────────────────────────
get_entitlements() {
    # Try ipsw first
    if command -v ipsw &>/dev/null; then
        ipsw macho info "$BINARY" --ent 2>/dev/null
        return
    fi
    # Try jtool2
    if command -v jtool2 &>/dev/null; then
        jtool2 --ent "$BINARY" 2>/dev/null
        return
    fi
    # Try codesign
    codesign -d --entitlements :- "$BINARY" 2>/dev/null
}

# ── Get Mach-O flags ──────────────────────────────────────────────────────────
get_macho_info() {
    if command -v ipsw &>/dev/null; then
        ipsw macho info "$BINARY" 2>/dev/null
        return
    fi
    otool -hv "$BINARY" 2>/dev/null
}

# ── Load data ─────────────────────────────────────────────────────────────────
ENTITLEMENTS=$(get_entitlements)
MACHO_INFO=$(get_macho_info)

# ── Report header ─────────────────────────────────────────────────────────────
printf "\n"
printf "${BOLD}╔══════════════════════════════════════════════════════╗${R}\n"
printf "${BOLD}║         BINARY PROTECTION SHIELD REPORT              ║${R}\n"
printf "${BOLD}╚══════════════════════════════════════════════════════╝${R}\n"
printf "${DIM}  Binary: %s${R}\n\n" "$BINARY"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Mach-O Binary Flags
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$MODE" == "both" || "$MODE" == "macho" ]]; then
    printf "${BOLD}${CYAN}▶ MACH-O BINARY FLAGS${R}\n\n"

    # PIE — Position Independent Executable
    if echo "$MACHO_INFO" | grep -qiE "PIE|pie"; then
        check "PIE (Position Independent Executable)" "present" "ASLR enabled — base address randomized on every launch"
    else
        check "PIE (Position Independent Executable)" "missing_critical" "No ASLR — binary loads at fixed address, trivial to exploit"
    fi

    # Stack Canaries
    if echo "$MACHO_INFO" | grep -qiE "stack.chk|___stack_chk_guard|stack_canary"; then
        check "Stack Canaries" "present" "Stack overflow protection enabled"
    else
        check "Stack Canaries" "missing_warn" "No stack canaries — stack overflow attacks easier"
    fi

    # ARC (Automatic Reference Counting)
    if echo "$MACHO_INFO" | grep -qiE "objc_retain|objc_release|arc"; then
        check "ARC (Automatic Reference Counting)" "present" "Memory management via ARC"
    else
        check "ARC (Automatic Reference Counting)" "missing_warn" "No ARC symbols — manual memory management or stripped"
    fi

    # Encryption
    if echo "$MACHO_INFO" | grep -qiE "LC_ENCRYPTION_INFO"; then
        cryptid=$(echo "$MACHO_INFO" | grep -i "cryptid" | grep -o "[0-9]" | head -1)
        if [[ "$cryptid" == "1" ]]; then
            check "Binary Encryption (FairPlay)" "present" "cryptid=1 — encrypted by App Store"
        else
            check "Binary Encryption (FairPlay)" "missing_warn" "cryptid=0 — not encrypted (dev/sideloaded build)"
        fi
    else
        check "Binary Encryption (FairPlay)" "missing_warn" "No LC_ENCRYPTION_INFO — not an App Store build"
    fi

    # Weak symbols / stripped
    if echo "$MACHO_INFO" | grep -qiE "LC_SYMTAB"; then
        num_syms=$(echo "$MACHO_INFO" | grep -i "Num Syms" | grep -o "[0-9]*" | head -1)
        if [[ -n "$num_syms" && "$num_syms" -gt 100 ]]; then
            check "Symbol Table Stripped" "missing_warn" "Num Syms: $num_syms — symbols present, easier to reverse"
        else
            check "Symbol Table Stripped" "present" "Symbol table stripped or minimal"
        fi
    fi

    # Objective-C runtime
    if echo "$MACHO_INFO" | grep -qiE "__objc_classlist|__objc_methname"; then
        check "ObjC Runtime Metadata" "info" "ObjC metadata present — class-dump possible"
    fi

    # Swift metadata
    if echo "$MACHO_INFO" | grep -qiE "__swift5_types|__swift5_proto"; then
        check "Swift Metadata" "info" "Swift type metadata present — swift-dump possible"
    fi

    # HasTLVDescriptors
    if echo "$MACHO_INFO" | grep -qiE "HasTLVDescriptors"; then
        check "Thread Local Variables" "info" "HasTLVDescriptors — thread-local storage in use"
    fi

    printf "\n"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Entitlements
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$MODE" == "both" || "$MODE" == "ent" ]]; then
    printf "${BOLD}${MAGENTA}▶ ENTITLEMENTS${R}\n\n"

    if [[ -z "$ENTITLEMENTS" ]]; then
        printf "  ${DIM}No entitlements found or could not extract.${R}\n\n"
    else

        # ── get-task-allow ──
        if echo "$ENTITLEMENTS" | grep -q "get-task-allow"; then
            val=$(echo "$ENTITLEMENTS" | grep -A1 "get-task-allow" | grep -o "true\|false")
            if [[ "$val" == "true" ]]; then
                check "get-task-allow" "missing_critical" "true — debuggers can attach (dev build, NOT for production)"
            else
                check "get-task-allow" "present" "false — debugger attachment blocked"
            fi
        else
            check "get-task-allow" "present" "not set — debugger attachment blocked by default"
        fi

        # ── Hardened Process (MIE) ──
        if echo "$ENTITLEMENTS" | grep -q "com.apple.security.hardened-process<"; then
            check "Hardened Process (MIE)" "present" "Memory Isolation Enhancements enabled"
        else
            check "Hardened Process (MIE)" "missing_critical" "No hardened-process — memory attacks easier (heap spray, ROP)"
        fi

        # ── Hardened Heap ──
        if echo "$ENTITLEMENTS" | grep -q "hardened-heap"; then
            check "Hardened Heap" "present" "Heap hardening active — use-after-free harder to exploit"
        else
            check "Hardened Heap" "missing_warn" "No hardened-heap — heap vulnerabilities easier to exploit"
        fi

        # ── checked-allocations ──
        if echo "$ENTITLEMENTS" | grep -q "checked-allocations"; then
            check "Checked Allocations (MIE)" "present" "Allocation integrity checks enabled"
        else
            check "Checked Allocations (MIE)" "missing_warn" "No checked-allocations — memory corruption harder to detect"
        fi

        # ── dyld-ro ──
        if echo "$ENTITLEMENTS" | grep -q "dyld-ro"; then
            check "dyld Read-Only (dyld-ro)" "present" "dyld data marked read-only — dyld attacks mitigated"
        else
            check "dyld Read-Only (dyld-ro)" "missing_warn" "No dyld-ro — dyld data writable, hook injection easier"
        fi

        # ── platform-restrictions ──
        if echo "$ENTITLEMENTS" | grep -q "platform-restrictions"; then
            val=$(echo "$ENTITLEMENTS" | grep -A1 "platform-restrictions" | grep -o "[0-9]*" | head -1)
            check "Platform Restrictions (MIE)" "present" "value=$val — platform security restrictions active"
        else
            check "Platform Restrictions (MIE)" "missing_warn" "No platform-restrictions — weaker runtime isolation"
        fi

        # ── enhanced-security-version ──
        if echo "$ENTITLEMENTS" | grep -q "enhanced-security-version"; then
            val=$(echo "$ENTITLEMENTS" | grep -A1 "enhanced-security-version" | grep -o "[0-9]*" | head -1)
            check "Enhanced Security Version (MIE)" "present" "version=$val"
        else
            check "Enhanced Security Version (MIE)" "missing_warn" "No enhanced-security-version"
        fi

        # ── keychain sharing ──
        if echo "$ENTITLEMENTS" | grep -q "keychain-access-groups"; then
            groups=$(echo "$ENTITLEMENTS" | grep -A5 "keychain-access-groups" | grep "<string>" | sed 's/.*<string>\(.*\)<\/string>.*/\1/')
            check "Keychain Access Groups" "info" "Shared keychain: $(echo $groups | tr '\n' ' ')"
        fi

        # ── app groups ──
        if echo "$ENTITLEMENTS" | grep -q "com.apple.security.application-groups"; then
            check "App Groups" "info" "Shared container between apps — verify data exposure"
        fi

        # ── push notifications ──
        if echo "$ENTITLEMENTS" | grep -q "aps-environment"; then
            val=$(echo "$ENTITLEMENTS" | grep -A1 "aps-environment" | grep -o "production\|development")
            check "Push Notifications (APS)" "info" "environment=$val"
        fi

        # ── iCloud ──
        if echo "$ENTITLEMENTS" | grep -qiE "com.apple.developer.icloud"; then
            check "iCloud Entitlements" "info" "iCloud access configured — verify data stored in cloud"
        fi

        # ── extended virtual addressing ──
        if echo "$ENTITLEMENTS" | grep -q "com.apple.developer.kernel.extended-virtual-addressing"; then
            check "Extended Virtual Addressing" "info" "Large memory space — unusual for most apps"
        fi

        # ── increased memory limit ──
        if echo "$ENTITLEMENTS" | grep -q "com.apple.developer.kernel.increased-memory-limit"; then
            check "Increased Memory Limit" "info" "Higher RAM limit requested"
        fi

        # ── Team ID ──
        team=$(echo "$ENTITLEMENTS" | grep -A1 "com.apple.developer.team-identifier" | grep "<string>" | sed 's/.*<string>\(.*\)<\/string>.*/\1/')
        if [[ -n "$team" ]]; then
            check "Team Identifier" "info" "$team"
        fi

        # ── Bundle ID ──
        bundle=$(echo "$ENTITLEMENTS" | grep -A1 "application-identifier" | grep "<string>" | sed 's/.*<string>\(.*\)<\/string>.*/\1/')
        if [[ -n "$bundle" ]]; then
            check "Application Identifier" "info" "$bundle"
        fi

        printf "\n"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — What Should Be Present (Missing Summary)
# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}${RED}▶ MISSING PROTECTIONS — RECOMMENDATIONS${R}\n\n"

if [[ "$MODE" == "both" || "$MODE" == "macho" ]]; then
    if ! echo "$MACHO_INFO" | grep -qiE "PIE|pie"; then
        printf "  ${RED}${BOLD}[CRITICAL]${R} Enable PIE — add -pie linker flag\n"
        printf "             ${DIM}Allows ASLR to randomize the binary base address${R}\n\n"
    fi
fi

if [[ "$MODE" == "both" || "$MODE" == "ent" ]] && [[ -n "$ENTITLEMENTS" ]]; then
    if echo "$ENTITLEMENTS" | grep -q "get-task-allow" && \
       echo "$ENTITLEMENTS" | grep -A1 "get-task-allow" | grep -q "true"; then
        printf "  ${RED}${BOLD}[CRITICAL]${R} Remove get-task-allow=true before App Store submission\n"
        printf "             ${DIM}Allows any debugger to attach to the process${R}\n\n"
    fi

    if ! echo "$ENTITLEMENTS" | grep -q "com.apple.security.hardened-process<"; then
        printf "  ${RED}${BOLD}[CRITICAL]${R} Enable Memory Isolation Enhancements (MIE)\n"
        printf "             ${DIM}Add com.apple.security.hardened-process entitlement${R}\n"
        printf "             ${DIM}Protects against heap spray, ROP chains, dyld injection${R}\n\n"
    fi

    if ! echo "$ENTITLEMENTS" | grep -q "hardened-heap"; then
        printf "  ${YELLOW}${BOLD}[WARN]${R}     Enable Hardened Heap\n"
        printf "             ${DIM}Add com.apple.security.hardened-process.hardened-heap${R}\n\n"
    fi

    if ! echo "$ENTITLEMENTS" | grep -q "checked-allocations"; then
        printf "  ${YELLOW}${BOLD}[WARN]${R}     Enable Checked Allocations\n"
        printf "             ${DIM}Add com.apple.security.hardened-process.checked-allocations${R}\n\n"
    fi

    if ! echo "$ENTITLEMENTS" | grep -q "dyld-ro"; then
        printf "  ${YELLOW}${BOLD}[WARN]${R}     Enable dyld Read-Only\n"
        printf "             ${DIM}Add com.apple.security.hardened-process.dyld-ro${R}\n\n"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}──────────────────────────────────────────────────────${R}\n"
printf "  ${BOLD}Summary${R}\n"
printf "  ${GREEN}${BOLD}Protections present  : %d${R}\n" "$n_present"
printf "  ${RED}${BOLD}Missing (critical)   : %d${R}\n"   "$n_missing_critical"
printf "  ${YELLOW}${BOLD}Missing (warning)    : %d${R}\n" "$n_missing_warn"

# Score
total=$(( n_present + n_missing_critical + n_missing_warn ))
if [[ $total -gt 0 ]]; then
    score=$(( n_present * 100 / total ))
    if [[ $score -ge 80 ]]; then
        printf "  ${GREEN}${BOLD}Security Score       : %d%%${R}\n" "$score"
    elif [[ $score -ge 50 ]]; then
        printf "  ${YELLOW}${BOLD}Security Score       : %d%%${R}\n" "$score"
    else
        printf "  ${RED}${BOLD}Security Score       : %d%%${R}\n" "$score"
    fi
fi
printf "${BOLD}──────────────────────────────────────────────────────${R}\n\n"
