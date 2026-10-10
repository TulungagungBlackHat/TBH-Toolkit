#!/bin/bash
# TBH-Toolkit Installer - Tulungagung Black Hat
# Clones the full TBH security toolset. Safe by design: only runs `git clone`.
set -u

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════╗"
echo -e "║  TBH-Toolkit Installer             ║"
echo -e "║  Tulungagung Black Hat             ║"
echo -e "╚════════════════════════════════════╝${NC}"
echo -e "[*] Installing TBH toolset..."

REPOS=(
  TBH-Recon TBH-SubFinder TBH-DirFinder TBH-ParamFinder TBH-JSLeak
  TBH-XSS TBH-SQLi TBH-LFI TBH-SSRF TBH-SSTI
  TBH-OpenRedirect TBH-IDOR TBH-CORS
  TBH-PortScanner TBH-PhishDetector TBH-PassStrength TBH-Utils
  TBH-AllScan TBH-BugBounty TBH-CLI
)

ok=0; fail=0
for repo in "${REPOS[@]}"; do
  if [ -d "$repo" ]; then
    echo -e "${CYAN}[=] $repo already exists, skipping${NC}"
    ok=$((ok+1))
    continue
  fi
  if git clone --depth 1 "https://github.com/TulungagungBlackHat/$repo" >/dev/null 2>&1; then
    echo -e "${GREEN}[✓] $repo${NC}"
    ok=$((ok+1))
  else
    echo -e "${RED}[✗] $repo (clone failed)${NC}"
    fail=$((fail+1))
  fi
done

echo ""
echo -e "${GREEN}[✓] Done: $ok installed, $fail failed${NC}"
echo "Start here:"
echo "  python3 TBH-Recon/main.py -u https://example.com --help"
echo "  python3 TBH-AllScan/allscan.py --help"
echo ""
echo "Authorized targets only. See SECURITY.md in each repo."
