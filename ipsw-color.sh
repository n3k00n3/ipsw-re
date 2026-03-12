#!/usr/bin/env bash
# ipsw-color.sh — Colorize output of ipsw macho info --swift / --objc
# Usage: ./ipsw-color.sh <binary> [--swift|--objc]

BINARY="$1"
MODE="${2:-}"

# ── Demangle setup ────────────────────────────────────────────────────────────
HAS_DEMANGLE=0
DEMANGLE_CMD=""

if command -v swift-demangle &>/dev/null; then
    HAS_DEMANGLE=1
    DEMANGLE_CMD="swift-demangle"
elif xcrun --find swift-demangle &>/dev/null 2>&1; then
    HAS_DEMANGLE=1
    DEMANGLE_CMD="xcrun swift-demangle"
fi

# Demangle a single symbol; returns empty string if unchanged (wasn't mangled)
demangle_symbol() {
    local sym="$1"
    local result
    result=$(printf '%s' "$sym" | $DEMANGLE_CMD 2>/dev/null)
    if [[ "$result" == "$sym" ]]; then
        echo ""
    else
        echo "$result"
    fi
}

# ── Legend ────────────────────────────────────────────────────────────────────
print_legend() {
    printf "\n\033[1m── LEGEND ───────────────────────────────────────\033[0m\n"
    printf "  \033[1;36mclass / @interface\033[0m       → Class\n"
    printf "  \033[1;33mstruct\033[0m                   → Struct\n"
    printf "  \033[1;35menum / case\033[0m              → Enum\n"
    printf "  \033[1;34mprotocol\033[0m                 → Protocol\n"
    printf "  \033[0;34mextension\033[0m                → Extension\n"
    printf "  \033[0;33mtypealias\033[0m                → Typealias\n"
    printf "  \033[2;35mopaque_type\033[0m              → Opaque type\n"
    printf "  \033[1;32mstatic func / +[]\033[0m        → Static method\n"
    printf "  \033[0;32mfunc / -[]\033[0m               → Instance method\n"
    printf "  \033[0;96mlet / var / ivar\033[0m         → Field\n"
    printf "  \033[0;95mvar lazy\033[0m                 → Lazy field\n"
    printf "  \033[0;37m@property\033[0m                → ObjC property\n"
    printf "  \033[2;36mprotocol conformance\033[0m     → Conformance\n"
    printf "  \033[2;33m  ↳ demangled (reference only — search with mangled)\033[0m\n"
    printf "\033[1m─────────────────────────────────────────────────\033[0m\n\n"
}

# ── Swift colorizer ───────────────────────────────────────────────────────────
colorize_swift() {
    local C_CLASS='\033[1;36m'
    local C_STRUCT='\033[1;33m'
    local C_ENUM='\033[1;35m'
    local C_PROTOCOL='\033[1;34m'
    local C_EXT='\033[0;34m'
    local C_ALIAS='\033[0;33m'
    local C_STATIC='\033[1;32m'
    local C_METHOD='\033[0;32m'
    local C_IVAR='\033[0;96m'
    local C_LAZY='\033[0;95m'
    local C_CONFORM='\033[2;36m'
    local C_WITNESS='\033[2;34m'
    local C_COMMENT='\033[2;32m'
    local C_BRACE='\033[2;37m'
    local C_CASE='\033[0;35m'
    local C_OPAQUE='\033[2;35m'
    local C_DEMANGLED='\033[2;33m'   # dim yellow — visual hint only
    local DIM='\033[2m'
    local RESET='\033[0m'

    while IFS= read -r line; do
        local color=""
        local show_demangled=0

        if [[ -z "$line" ]]; then
            echo ""; continue
        fi

        if [[ "$line" =~ ^opaque_type ]]; then
            color="$C_OPAQUE"
        elif [[ "$line" =~ ^protocol\ conformance ]]; then
            color="$C_CONFORM"
        elif [[ "$line" =~ ^extension\  ]]; then
            color="${C_EXT}\033[1m"
        elif [[ "$line" =~ ^[[:space:]]*typealias\  ]]; then
            color="$C_ALIAS"
        elif [[ "$line" =~ ^enum\  ]]; then
            color="${C_ENUM}\033[1m"
        elif [[ "$line" =~ ^struct\  ]]; then
            color="${C_STRUCT}\033[1m"
        elif [[ "$line" =~ ^class\  ]]; then
            color="${C_CLASS}\033[1m"
        elif [[ "$line" =~ ^protocol\  ]]; then
            color="${C_PROTOCOL}\033[1m"
        elif [[ "$line" =~ ^[[:space:]]*(static|class)\ func\  ]]; then
            color="$C_STATIC"; show_demangled=1
        elif [[ "$line" =~ ^[[:space:]]*func\  ]]; then
            color="$C_METHOD"; show_demangled=1
        elif [[ "$line" =~ ^[[:space:]]*var\ lazy\  ]]; then
            color="$C_LAZY"
        elif [[ "$line" =~ ^[[:space:]]*(let|var)\  ]]; then
            color="$C_IVAR"
        elif [[ "$line" =~ ^[[:space:]]*case\  ]]; then
            color="$C_CASE"
        elif [[ "$line" =~ ^[[:space:]]*\/\* ]]; then
            color="$C_COMMENT"
        elif [[ "$line" =~ ^[[:space:]]*\/\/ ]]; then
            color="$DIM"
        elif [[ "$line" =~ ^[[:space:]]*where\  ]]; then
            color="$DIM"
        elif [[ "$line" =~ ^[[:space:]]*[\{\}][[:space:]]*$ ]]; then
            color="$C_BRACE"
        elif [[ "$line" =~ ^[[:space:]]+_?\$[sS][A-Za-z0-9_] ]]; then
            color="$C_WITNESS"; show_demangled=1
        else
            color="$RESET"
        fi

        # Always print the original line (mangled) — safe to copy into Ghidra/Hopper
        printf "${color}%s${RESET}\n" "$line"

        # Below it, print the demangled version as a dim comment — for reading only
        if [[ $show_demangled -eq 1 && $HAS_DEMANGLE -eq 1 ]]; then
            local token
            token=$(echo "$line" | grep -oE '(_\$s|_\$S|\$s|\$S)[A-Za-z0-9_]+' | head -1)
            if [[ -n "$token" ]]; then
                local d
                d=$(demangle_symbol "$token")
                if [[ -n "$d" ]]; then
                    printf "${C_DEMANGLED}  ↳ %s${RESET}\n" "$d"
                fi
            fi
        fi

    done
}

# ── ObjC colorizer (awk — fast) ───────────────────────────────────────────────
colorize_objc() {
    awk '
    BEGIN {
        RESET      = "\033[0m"
        C_CLASS    = "\033[1;36m"
        C_PROTOCOL = "\033[1;34m"
        C_STATIC   = "\033[1;32m"
        C_METHOD   = "\033[0;32m"
        C_IVAR     = "\033[0;96m"
        C_PROP     = "\033[0;37m"
        C_COMMENT  = "\033[2;32m"
        C_BRACE    = "\033[2;37m"
        C_REQ      = "\033[0;90m"
    }
    /^@protocol/                  { print C_PROTOCOL "\033[1m" $0 RESET; next }
    /^@interface/                 { print C_CLASS "\033[1m" $0 RESET; next }
    /^@end/                       { print C_BRACE $0 RESET; next }
    /^@(required|optional)/       { print C_REQ $0 RESET; next }
    /^[[:space:]]*@property/      { print C_PROP $0 RESET; next }
    /^[[:space:]]*\+\[/           { print C_STATIC $0 RESET; next }
    /^[[:space:]]*-\[/            { print C_METHOD $0 RESET; next }
    /^[[:space:]]*\/\*/           { print C_COMMENT $0 RESET; next }
    /^\{|^\}/                     { print C_BRACE $0 RESET; next }
    /^[[:space:]]+[A-Za-z_].+;/  { print C_IVAR $0 RESET; next }
                                  { print RESET $0 }
    '
}

# ── Main ──────────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <binary> [--swift|--objc]"
    exit 1
fi

print_legend

if [[ $HAS_DEMANGLE -eq 0 ]]; then
    printf "\033[33m⚠  swift-demangle not found — demangled hints disabled.\033[0m\n\n"
fi

case "$MODE" in
    --swift)
        printf "\033[1m━━━ SWIFT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
        ipsw macho info "$BINARY" --swift 2>/dev/null | colorize_swift
        ;;
    --objc)
        printf "\033[1m━━━ OBJECTIVE-C ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
        ipsw macho info "$BINARY" --objc 2>/dev/null | colorize_objc
        ;;
    *)
        printf "\033[1m━━━ SWIFT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
        ipsw macho info "$BINARY" --swift 2>/dev/null | colorize_swift
        printf "\n\033[1m━━━ OBJECTIVE-C ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
        ipsw macho info "$BINARY" --objc 2>/dev/null | colorize_objc
        ;;
esac