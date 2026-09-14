#!/bin/bash
# TBH-Toolkit Installer - Tulungagung Black Hat
# 100% Aman - hanya clone repo TBH
echo -e "\033[91m╔════════════════════════════════════╗"
echo -e "║  TBH-Toolkit Installer - TBH       ║"
echo -e "║  Tulungagung Black Hat | uchil404  ║"
echo -e "╚════════════════════════════════════╝\033[0m"
echo "[*] Installing TBH Tools..."
for repo in TBH-Recon TBH-PhishDetector TBH-PortScanner TBH-PassStrength awesome-tulungagung; do
  echo -e "\033[96m[+] Cloning $repo...\033[0m"
  git clone https://github.com/TulungagungBlackHat/$repo 2>&1 | tail -n 1
done
echo -e "\033[92m[✓] All TBH tools installed! Check ./TBH-*/\033[0m"
echo "Usage: python3 TBH-Recon/main.py -u https://example.com --ports"
