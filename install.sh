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

# 3. Build both binaries (native arch).
say "building specter (this can take a minute on mobile)…"
CGO_ENABLED=0 go build -ldflags "-s -w" -o specter . || die "specter build failed"
ok "specter built: $(du -h specter | cut -f1)"

say "building vector (endpoint analyzer)…"
CGO_ENABLED=0 go build -ldflags "-s -w" -o vector ./cmd/vector || die "vector build failed"
ok "vector built: $(du -h vector | cut -f1)"

say "building phantom (subdomain/secret harvester)…"
CGO_ENABLED=0 go build -ldflags "-s -w" -o phantom ./cmd/phantom || die "phantom build failed"
ok "phantom built: $(du -h phantom | cut -f1)"

# 4. Install.
for b in specter vector phantom; do
    install -m 0755 "$b" "$BIN/$b" 2>/dev/null || cp "$b" "$BIN/$b"
    chmod +x "$BIN/$b"
    ok "installed $BIN/$b"
done

# 5. Verify.
if command -v specter >/dev/null 2>&1; then
    ok "ready! recon:    specter -d target.com -all"
    ok "      analyze:  vector  -i specter-out/target.com/endpoints.txt -min high"
    ok "      harvest:  phantom -u https://target.com -san same -sop secrets.txt"
else
    warn "add $BIN to your PATH, then run: specter -h  /  vector -h"
fi
