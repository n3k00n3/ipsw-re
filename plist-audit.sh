#!/usr/bin/env bash
# plist-audit.sh — Info.plist security auditor for iOS apps
# Usage:
#   ./plist-audit.sh <path/to/Info.plist>
#   ./plist-audit.sh <path/to/App.app>          # auto-finds Info.plist inside

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

# ── Arg parsing ───────────────────────────────────────────────────────────────
INPUT="$1"
if [[ -z "$INPUT" ]]; then
    printf "Usage: %s <Info.plist | App.app>\n" "$0"
    exit 1
fi

# Auto-find plist inside .app bundle
if [[ -d "$INPUT" ]]; then
    PLIST="$INPUT/Info.plist"
else
    PLIST="$INPUT"
fi

if [[ ! -f "$PLIST" ]]; then
    printf "Info.plist not found: %s\n" "$PLIST"
    exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
# Read a plist value by key (handles both binary and XML plists)
pval() {
    /usr/libexec/PlistBuddy -c "Print :$1" "$PLIST" 2>/dev/null
}

# Read nested key (dot-separated path)
pval_path() {
    /usr/libexec/PlistBuddy -c "Print :$1" "$PLIST" 2>/dev/null
}

# Check if key exists
pexists() {
    /usr/libexec/PlistBuddy -c "Print :$1" "$PLIST" 2>/dev/null | grep -q . && return 0 || return 1
}

# Convert binary plist to XML for grep-based analysis
XML=$(plutil -convert xml1 -o - "$PLIST" 2>/dev/null)
if [[ -z "$XML" ]]; then
    printf "Failed to parse plist: %s\n" "$PLIST"
    exit 1
fi

# ── Counters ──────────────────────────────────────────────────────────────────
n_critical=0
n_warn=0
n_info=0

flag_critical() { n_critical=$(( n_critical + 1 )); }
flag_warn()     { n_warn=$(( n_warn + 1 )); }
flag_info()     { n_info=$(( n_info + 1 )); }

# ── Header ────────────────────────────────────────────────────────────────────
printf "\n"
printf "${BOLD}╔══════════════════════════════════════════════════════╗${R}\n"
printf "${BOLD}║           INFO.PLIST SECURITY AUDIT                  ║${R}\n"
printf "${BOLD}╚══════════════════════════════════════════════════════╝${R}\n"
printf "${DIM}  File: %s${R}\n\n" "$PLIST"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — App Identity
# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}${CYAN}▶ APP IDENTITY${R}\n\n"

bundle_id=$(pval "CFBundleIdentifier")
bundle_name=$(pval "CFBundleName")
bundle_version=$(pval "CFBundleShortVersionString")
bundle_build=$(pval "CFBundleVersion")
min_os=$(pval "MinimumOSVersion")
sdk=$(pval "DTSDKName")
platform=$(pval "DTPlatformName")
bundle_exec=$(pval "CFBundleExecutable")

printf "  %-30s %s\n" "Bundle ID:"        "${bundle_id:-n/a}"
printf "  %-30s %s\n" "App Name:"         "${bundle_name:-n/a}"
printf "  %-30s %s\n" "Version:"          "${bundle_version:-n/a} (build ${bundle_build:-n/a})"
printf "  %-30s %s\n" "Minimum iOS:"      "${min_os:-n/a}"
printf "  %-30s %s\n" "SDK:"              "${sdk:-n/a}"
printf "  %-30s %s\n" "Platform:"         "${platform:-n/a}"
printf "  %-30s %s\n" "Executable:"       "${bundle_exec:-n/a}"
printf "\n"

# Warn on old min OS
if [[ -n "$min_os" ]]; then
    major=$(echo "$min_os" | cut -d. -f1)
    if [[ "$major" -lt 13 ]]; then
        printf "  ${YELLOW}⚠  MinimumOSVersion %s — supports old iOS, larger attack surface${R}\n\n" "$min_os"
        flag_warn
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — ATS (App Transport Security)
# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}${RED}▶ APP TRANSPORT SECURITY (ATS)${R}\n\n"

ats_exists=$(echo "$XML" | grep -c "NSAppTransportSecurity")

if [[ "$ats_exists" -eq 0 ]]; then
    printf "  ${GREEN}✓  No ATS configuration found — default ATS enforced${R}\n\n"
    flag_info
else
    # NSAllowsArbitraryLoads
    if echo "$XML" | grep -q "NSAllowsArbitraryLoads"; then
        val=$(echo "$XML" | grep -A1 "NSAllowsArbitraryLoads" | grep -o "<true/>\|<false/>")
        if [[ "$val" == "<true/>" ]]; then
            printf "  ${RED}${BOLD}✗  NSAllowsArbitraryLoads = true — ALL HTTP traffic allowed (no TLS required)${R}\n"
            flag_critical
        else
            printf "  ${GREEN}✓  NSAllowsArbitraryLoads = false${R}\n"
        fi
    fi

    # NSAllowsArbitraryLoadsInWebContent
    if echo "$XML" | grep -q "NSAllowsArbitraryLoadsInWebContent"; then
        val=$(echo "$XML" | grep -A1 "NSAllowsArbitraryLoadsInWebContent" | grep -o "<true/>\|<false/>")
        if [[ "$val" == "<true/>" ]]; then
            printf "  ${YELLOW}⚠  NSAllowsArbitraryLoadsInWebContent = true — WebViews bypass ATS${R}\n"
            flag_warn
        fi
    fi

    # NSAllowsLocalNetworking
    if echo "$XML" | grep -q "NSAllowsLocalNetworking"; then
        val=$(echo "$XML" | grep -A1 "NSAllowsLocalNetworking" | grep -o "<true/>\|<false/>")
        if [[ "$val" == "<true/>" ]]; then
            printf "  ${YELLOW}⚠  NSAllowsLocalNetworking = true — local HTTP allowed${R}\n"
            flag_warn
        fi
    fi

    # NSExceptionDomains — list each domain and its exceptions
    if echo "$XML" | grep -q "NSExceptionDomains"; then
        printf "\n  ${BOLD}Exception Domains:${R}\n"
        # Extract domain names between NSExceptionDomains block
        echo "$XML" | awk '
            /NSExceptionDomains/{found=1; next}
            found && /<key>/{
                gsub(/<\/?key>/,"")
                gsub(/^[[:space:]]*/,"")
                domain=$0
                printf "    domain: %s\n", domain
            }
            found && /NSExceptionAllowsInsecureHTTPLoads/{
                getline; if (/true/) printf "      ↳ NSExceptionAllowsInsecureHTTPLoads = TRUE  [CRITICAL]\n"
            }
            found && /NSIncludesSubdomains/{
                getline; if (/true/) printf "      ↳ NSIncludesSubdomains = true\n"
            }
            found && /NSExceptionMinimumTLSVersion/{
                getline
                gsub(/<\/?string>/,"")
                gsub(/^[[:space:]]*/,"")
                printf "      ↳ MinimumTLSVersion = %s\n", $0
            }
            found && /NSExceptionRequiresForwardSecrecy/{
                getline; if (/false/) printf "      ↳ NSExceptionRequiresForwardSecrecy = FALSE  [WARN]\n"
            }
            found && /<\/dict>.*<\/dict>/{found=0}
        '
    fi
    printf "\n"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — URL Schemes (deep links)
# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}${MAGENTA}▶ URL SCHEMES (Deep Links)${R}\n\n"

if echo "$XML" | grep -q "CFBundleURLTypes"; then
    schemes=$(echo "$XML" | awk '
        /CFBundleURLSchemes/{found=1; next}
        found && /<string>/{
            gsub(/<\/?string>/,"")
            gsub(/^[[:space:]]*/,"")
            print "  " $0
            found=0
        }
    ')
    if [[ -n "$schemes" ]]; then
        echo "$schemes" | while IFS= read -r scheme; do
            printf "  ${MAGENTA}${BOLD}%-30s${R}" "$scheme"
            # Flag custom schemes that look sensitive
            lower=$(echo "$scheme" | tr '[:upper:]' '[:lower:]')
            if echo "$lower" | grep -qiE "oauth|auth|login|pay|bank|token|sso"; then
                printf "  ${YELLOW}⚠  auth/payment scheme — verify handler validation${R}"
                flag_warn
            fi
            printf "\n"
        done
        printf "\n  ${DIM_YELLOW}↳ Deep link hijacking: any app can register these schemes${R}\n"
        flag_warn
    fi
else
    printf "  ${DIM}No URL schemes registered${R}\n"
fi
printf "\n"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Permissions
# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}${YELLOW}▶ PERMISSIONS (Privacy Usage Descriptions)${R}\n\n"

declare -a PERMISSION_KEYS=(
    "NSCameraUsageDescription:Camera"
    "NSMicrophoneUsageDescription:Microphone"
    "NSLocationWhenInUseUsageDescription:Location (when in use)"
    "NSLocationAlwaysUsageDescription:Location (always)"
    "NSLocationAlwaysAndWhenInUseUsageDescription:Location (always + when in use)"
    "NSContactsUsageDescription:Contacts"
    "NSPhotoLibraryUsageDescription:Photo Library (read)"
    "NSPhotoLibraryAddUsageDescription:Photo Library (write)"
    "NSFaceIDUsageDescription:Face ID"
    "NSMotionUsageDescription:Motion / Accelerometer"
    "NSHealthShareUsageDescription:HealthKit (read)"
    "NSHealthUpdateUsageDescription:HealthKit (write)"
    "NSBluetoothAlwaysUsageDescription:Bluetooth"
    "NSLocalNetworkUsageDescription:Local Network"
    "NSSpeechRecognitionUsageDescription:Speech Recognition"
    "NSUserTrackingUsageDescription:App Tracking (ATT)"
    "NFCReaderUsageDescription:NFC"
    "NSCalendarsUsageDescription:Calendars"
    "NSRemindersUsageDescription:Reminders"
    "NSAppleMusicUsageDescription:Apple Music / Media Library"
)

found_perms=0
for entry in "${PERMISSION_KEYS[@]}"; do
    key=$(echo "$entry" | cut -d: -f1)
    label=$(echo "$entry" | cut -d: -f2-)
    if echo "$XML" | grep -q "$key"; then
        desc=$(echo "$XML" | grep -A1 "$key" | grep "<string>" | sed 's/.*<string>\(.*\)<\/string>.*/\1/' | head -1)
        printf "  ${YELLOW}${BOLD}%-35s${R} ${DIM}%s${R}\n" "$label" "${desc:0:60}"
        found_perms=$(( found_perms + 1 ))
        flag_info

        # Flag overly broad location
        if [[ "$key" == "NSLocationAlwaysUsageDescription" ]]; then
            printf "  ${DIM_RED}  ↳ Always location — verify if background tracking is justified${R}\n"
            flag_warn
        fi
        if [[ "$key" == "NSUserTrackingUsageDescription" ]]; then
            printf "  ${DIM_RED}  ↳ ATT — app requests cross-app tracking permission${R}\n"
            flag_warn
        fi
    fi
done

if [[ $found_perms -eq 0 ]]; then
    printf "  ${DIM}No privacy permission keys found${R}\n"
fi
printf "\n"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — Capabilities & Background Modes
# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}${BLUE}▶ CAPABILITIES & BACKGROUND MODES${R}\n\n"

if echo "$XML" | grep -q "UIBackgroundModes"; then
    printf "  ${BOLD}Background Modes:${R}\n"
    echo "$XML" | awk '
        /UIBackgroundModes/{found=1; next}
        found && /<string>/{
            gsub(/<\/?string>/,"")
            gsub(/^[[:space:]]*/,"")
            printf "    %s\n", $0
        }
        found && /<\/array>/{found=0}
    ' | while IFS= read -r mode; do
        printf "  ${BLUE}${BOLD}  %-30s${R}" "$mode"
        case "$mode" in
            *fetch*)       printf "  ${DIM_YELLOW}↳ background fetch — periodic data refresh${R}" ;;
            *location*)    printf "  ${DIM_RED}↳ background location — continuous tracking${R}"; flag_warn ;;
            *voip*)        printf "  ${DIM_YELLOW}↳ VoIP — persistent background socket${R}" ;;
            *remote-notification*) printf "  ${DIM}↳ push notifications${R}" ;;
            *processing*)  printf "  ${DIM}↳ background processing tasks${R}" ;;
        esac
        printf "\n"
    done
    printf "\n"
else
    printf "  ${DIM}No background modes declared${R}\n\n"
fi

# App uses encryption export compliance
if echo "$XML" | grep -q "ITSAppUsesNonExemptEncryption"; then
    val=$(echo "$XML" | grep -A1 "ITSAppUsesNonExemptEncryption" | grep -o "<true/>\|<false/>")
    if [[ "$val" == "<true/>" ]]; then
        printf "  ${YELLOW}⚠  ITSAppUsesNonExemptEncryption = true — app uses custom encryption (export compliance)${R}\n"
        flag_warn
    else
        printf "  ${DIM}ITSAppUsesNonExemptEncryption = false${R}\n"
    fi
    printf "\n"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Exported Keys / Hardcoded Secrets
# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}${RED}▶ POTENTIAL HARDCODED SECRETS${R}\n\n"

# Patterns that suggest API keys or tokens in plist values
SECRET_PATTERNS="key|token|secret|api|password|passwd|credential|auth|client_id|client_secret|firebase|google|aws|azure|stripe|twilio|sendgrid|mixpanel|segment|amplitude"

found_secrets=0
echo "$XML" | awk '
    /<key>/{
        gsub(/<\/?key>/,"")
        gsub(/^[[:space:]]*/,"")
        current_key=$0
    }
    /<string>/{
        gsub(/<\/?string>/,"")
        gsub(/^[[:space:]]*/,"")
        val=$0
        print current_key "|" val
    }
' | while IFS='|' read -r k v; do
    key_lower=$(echo "$k" | tr '[:upper:]' '[:lower:]')
    val_lower=$(echo "$v" | tr '[:upper:]' '[:lower:]')

    # Match suspicious key names
    if echo "$key_lower" | grep -qiE "$SECRET_PATTERNS"; then
        # Skip obvious non-secrets
        if echo "$v" | grep -qiE "^(YES|NO|true|false|[0-9]+)$"; then
            continue
        fi
        if [[ ${#v} -lt 8 ]]; then
            continue
        fi
        printf "  ${RED}${BOLD}%-40s${R} ${DIM_RED}%s${R}\n" "$k" "${v:0:80}"
        flag_critical
        found_secrets=$(( found_secrets + 1 ))
        continue
    fi

    # Match suspicious value patterns (looks like a key/token)
    if echo "$v" | grep -qiE "^[A-Za-z0-9_\-]{20,}$"; then
        if echo "$key_lower" | grep -qiE "$SECRET_PATTERNS"; then
            printf "  ${YELLOW}⚠  %-38s${R} ${DIM}%s${R}\n" "$k" "${v:0:80}"
            flag_warn
        fi
    fi

    # Firebase / Google config
    if echo "$key_lower" | grep -qiE "google|firebase|gcm|gms"; then
        printf "  ${YELLOW}⚠  %-38s${R} ${DIM}%s${R}\n" "$k" "${v:0:80}"
        flag_warn
    fi
done

printf "\n"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — Queried URL Schemes (LSApplicationQueriesSchemes)
# ══════════════════════════════════════════════════════════════════════════════
if echo "$XML" | grep -q "LSApplicationQueriesSchemes"; then
    printf "${BOLD}${DIM}▶ QUERIED URL SCHEMES (canOpenURL targets)${R}\n\n"
    echo "$XML" | awk '
        /LSApplicationQueriesSchemes/{found=1; next}
        found && /<string>/{
            gsub(/<\/?string>/,"")
            gsub(/^[[:space:]]*/,"")
            printf "  %s\n", $0
        }
        found && /<\/array>/{found=0}
    '
    printf "  ${DIM_YELLOW}↳ App checks if these apps are installed (device fingerprinting risk)${R}\n\n"
    flag_info
fi

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}──────────────────────────────────────────────────────${R}\n"
printf "  ${BOLD}Summary${R}\n"
printf "  ${RED}${BOLD}Critical findings : %d${R}\n" "$n_critical"
printf "  ${YELLOW}${BOLD}Warnings          : %d${R}\n" "$n_warn"
printf "  ${DIM}Informational     : %d${R}\n" "$n_info"
printf "${BOLD}──────────────────────────────────────────────────────${R}\n\n"
