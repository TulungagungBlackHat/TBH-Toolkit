#!/bin/bash
# TBH installer - one repo, one command.
# Safe by design: git clone + pip install requests only.
set -u

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; NC='\033[0m'
REPO_URL="https://github.com/TulungagungBlackHat/TBH-Toolkit"
DEST="${1:-TBH-Toolkit}"

echo -e "${RED}TBH toolkit installer${NC}"
echo -e "${CYAN}(authorized testing only, obviously)${NC}"

if [ -d "$DEST" ]; then
  echo -e "${CYAN}[=] $DEST exists, skipping clone${NC}"
else
  git clone --depth 1 "$REPO_URL" "$DEST" || {
    echo -e "${RED}[✗] clone failed${NC}"; exit 1; }
  echo -e "${GREEN}[+] cloned $DEST${NC}"
fi

cd "$DEST" || exit 1
chmod +x tbh

if python3 -c "import requests" 2>/dev/null; then
  echo -e "${GREEN}[+] requests already installed${NC}"
else
  python3 -m pip install --user requests && echo -e "${GREEN}[+] requests installed${NC}" \
    || echo -e "${RED}[!] pip failed - run: python3 -m pip install requests${NC}"
fi

echo ""
echo -e "${GREEN}[+] done. try:${NC}"
echo "  python3 $DEST/tbh          # menu"
echo "  python3 $DEST/tbh list"
echo ""
echo "Authorized targets only."
