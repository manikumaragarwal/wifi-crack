#!/bin/bash
# setup.sh — run once on Linux Mint to install everything needed
# usage: sudo bash setup.sh

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[!] run with sudo: sudo bash setup.sh"
    exit 1
fi

echo "[*] updating packages..."
apt update

echo "[*] installing core tools..."
apt install -y aircrack-ng hcxdumptool hcxtools hashcat macchanger net-tools wireless-tools

echo "[*] installing alfa adapter driver (rtl8812au)..."
apt install -y dkms git build-essential linux-headers-$(uname -r)

if [ ! -d "/tmp/rtl8812au" ]; then
    git clone https://github.com/aircrack-ng/rtl8812au.git /tmp/rtl8812au
fi
cd /tmp/rtl8812au
make && make install

echo "[*] downloading rockyou wordlist..."
WORDLIST_DIR="$(dirname "$0")/wordlists"
mkdir -p "$WORDLIST_DIR"
if [ ! -f "$WORDLIST_DIR/rockyou.txt" ]; then
    if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
        gunzip -k /usr/share/wordlists/rockyou.txt.gz -c > "$WORDLIST_DIR/rockyou.txt"
    else
        echo "[*] downloading rockyou.txt (~140MB)..."
        wget -q --show-progress -O "$WORDLIST_DIR/rockyou.txt.gz" \
            https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
        # the above is the raw txt despite the name
        mv "$WORDLIST_DIR/rockyou.txt.gz" "$WORDLIST_DIR/rockyou.txt" 2>/dev/null || true
    fi
fi

echo ""
echo "[+] setup complete. plug in the alfa adapter and run:"
echo "    sudo bash crack.sh"
