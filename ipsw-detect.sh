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

# ── Load wordlist (strip comments and blank lines) — bash 3 compatible ────────
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

# Build grep pattern: word1|word2|... via explicit loop (bash 3, no paste, no IFS trick)
GREP_PATTERN=""
for _p in "${PATTERNS[@]}"; do
    if [[ -z "$GREP_PATTERN" ]]; then
        GREP_PATTERN="$_p"
    else
        GREP_PATTERN="${GREP_PATTERN}|${_p}"
    fi
done

# ── Temp files (no associative arrays — bash 3 compat) ───────────────────────
WORK_DIR=$(mktemp -d)
CLASSES_FILE="$WORK_DIR/classes.txt"
METHODS_FILE="$WORK_DIR/methods.txt"
touch "$CLASSES_FILE" "$METHODS_FILE"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# ── Parser ────────────────────────────────────────────────────────────────────
# Each record written as: SOURCE\tDECL\tMATCHED  (tab-separated, no leading |)
parse_output() {
    local source="$1"
    local current_type=""

    while IFS= read -r line; do

        # ── Type declaration line ──
        if [[ "$line" =~ ^(class|struct|enum|protocol|extension)[[:space:]] ]]; then
            current_type="$line"
            if echo "$line" | grep -qiE "$GREP_PATTERN"; then
                local matched
                matched=$(echo "$line" | grep -oiE "$GREP_PATTERN" | sort -u | tr '\n' ' ')
                printf '%s\t%s\t%s\n' "$source" "$line" "$matched" >> "$CLASSES_FILE"
            fi
            continue
        fi

        # ── Member line ──
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

# ── Run ipsw ──────────────────────────────────────────────────────────────────
printf "${DIM}  Scanning %s ...${R}\n" "$BINARY"

if [[ "$MODE" == "both" || "$MODE" == "swift" ]]; then
    ipsw macho info "$BINARY" --swift 2>/dev/null | parse_output "Swift"
fi
if [[ "$MODE" == "both" || "$MODE" == "objc" ]]; then
    ipsw macho info "$BINARY" --objc  2>/dev/null | parse_output "ObjC"
fi

# ── Count results ─────────────────────────────────────────────────────────────
n_classes=$(grep -c "" "$CLASSES_FILE" 2>/dev/null || echo 0)
n_methods=$(grep -c "" "$METHODS_FILE" 2>/dev/null || echo 0)

# Count unique parents from METHODS_FILE (field 1, tab-separated)
n_parents=0
if [[ $n_methods -gt 0 ]]; then
    n_parents=$(cut -f1 "$METHODS_FILE" | sort -u | wc -l | tr -d ' ')
fi

total=$(( n_classes + n_methods ))

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
printf "  Suspicious type declarations : ${RED}${BOLD}%d${R}\n"  "$n_classes"
printf "  Types with suspicious members: ${YELLOW}${BOLD}%d${R}\n" "$n_parents"
printf "  Total suspicious members     : ${YELLOW}${BOLD}%d${R}\n" "$n_methods"
printf "${BOLD}──────────────────────────────────────────────────────${R}\n\n"