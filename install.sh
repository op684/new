#!/data/data/com.termux/files/usr/bin/bash
#
# SPECTER installer — optimized for Termux on rooted Android (OnePlus 7 Pro / arm64).
# Also works on any Linux box with Go installed.
#
# Usage:  bash install.sh
#
set -e

GREEN='\033[38;2;0;255;65m'; CYAN='\033[38;2;0;220;255m'
RED='\033[38;2;255;60;60m'; YEL='\033[38;2;255;215;0m'; RST='\033[0m'

say()  { printf "${CYAN}[*]${RST} %s\n" "$1"; }
ok()   { printf "${GREEN}[+]${RST} %s\n" "$1"; }
warn() { printf "${YEL}[!]${RST} %s\n" "$1"; }
die()  { printf "${RED}[x]${RST} %s\n" "$1"; exit 1; }

printf "${GREEN}"
cat <<'EOF'
   ___ ___ ___ ___ _____ ___ ___
  / __| _ \ __/ __|_   _| __| _ \
  \__ \  _/ _| (__  | | | _||   /
  |___/_| |___\___| |_| |___|_|_\   installer
EOF
printf "${RST}\n"

# 1. Pick a bin dir.
if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ]; then
    BIN="$PREFIX/bin"            # Termux
else
    BIN="$HOME/.local/bin"
    mkdir -p "$BIN"
fi
say "install target: $BIN"

# 2. Ensure Go is present.
if ! command -v go >/dev/null 2>&1; then
    warn "Go toolchain not found."
    if [ -n "$PREFIX" ]; then
        say "installing Go via pkg (Termux)…"
        pkg install -y golang || die "could not install Go — run: pkg install golang"
    else
        die "install Go first: https://go.dev/dl/"
    fi
fi
ok "go: $(go version)"

# 3. Build (native arch).
say "building specter (this can take a minute on mobile)…"
CGO_ENABLED=0 go build -ldflags "-s -w" -o specter . || die "build failed"
ok "binary built: $(du -h specter | cut -f1)"

# 4. Install.
install -m 0755 specter "$BIN/specter" 2>/dev/null || cp specter "$BIN/specter"
chmod +x "$BIN/specter"
ok "installed to $BIN/specter"

# 5. Verify.
if command -v specter >/dev/null 2>&1; then
    ok "ready! run:  specter -d target.com -all -theme cyberpunk"
else
    warn "add $BIN to your PATH, then run: specter -h"
fi
