#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  build.sh  —  Cipher Engine Launcher v2.0  (Linux / WSL build script)
#
#  Just run:  bash build.sh
#  No copying needed — files are read from their original locations.
#
#  OUTPUT:
#    CipherLauncher  ← single self-contained binary, nothing else needed
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[  OK  ]${NC}  $*"; }
fail() { echo -e "  ${RED}[ FAIL ]${NC}  $*"; exit 1; }
warn() { echo -e "  ${YELLOW}[ WARN ]${NC}  $*"; }
step() { echo -e "  ${CYAN}[ .... ]${NC}  $*"; }

echo -e "\n  ${YELLOW}══════════════════════════════════════════════════${NC}"
echo    "   Cipher Engine Launcher v2.0 — Linux Build"
echo -e "  ${YELLOW}══════════════════════════════════════════════════${NC}\n"

# ── Sanity checks ─────────────────────────────────────────────────────────────
step "Checking build tools ..."
command -v g++      >/dev/null 2>&1 || fail "g++ not found.      Install: sudo apt install build-essential"
command -v xz       >/dev/null 2>&1 || fail "xz not found.       Install: sudo apt install xz-utils"
command -v objcopy  >/dev/null 2>&1 || fail "objcopy not found.  Install: sudo apt install binutils"
command -v strip    >/dev/null 2>&1 || fail "strip not found.    Install: sudo apt install binutils"

# Optional: UPX for packing
UPX_AVAILABLE=0
if command -v upx >/dev/null 2>&1; then
    UPX_AVAILABLE=1
    ok "g++, xz, objcopy, strip, upx found"
else
    warn "upx not found — packing step will be skipped (optional: sudo apt install upx)"
    ok "g++, xz, objcopy, strip found"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  Resource file locations — original paths, no copying required
# ══════════════════════════════════════════════════════════════════════════════
SF_SRC="/mnt/c/Users/algorithm/Downloads/fairy-stockfish-largeboard_x86-64-modern"
NNUE_SRC="/mnt/c/Users/algorithm/Downloads/cipher_v2/cipher_project/res/nn-46832cfbead3.nnue.xz"
ICON_SRC="$SCRIPT_DIR/res/cipherlogo.png"

# ── Verify all three files exist ──────────────────────────────────────────────
step "Locating resource files ..."

[[ -f "$SF_SRC" ]]   || fail "Fairy-Stockfish not found at:\n         $SF_SRC"
[[ -f "$NNUE_SRC" ]] || fail "NNUE weights not found at:\n         $NNUE_SRC"
[[ -f "$ICON_SRC" ]] || fail "Icon not found at:\n         $ICON_SRC"

chmod +x "$SF_SRC"
ok "fairy-stockfish          $(du -sh "$SF_SRC"   | cut -f1)   ← $SF_SRC"
ok "nn-46832cfbead3.nnue.xz  $(du -sh "$NNUE_SRC" | cut -f1)   ← $NNUE_SRC"
ok "cipherlogo.png           $(du -sh "$ICON_SRC"  | cut -f1)   ← $ICON_SRC"

# ══════════════════════════════════════════════════════════════════════════════
#  Stable symlinks so objcopy symbol names match the C++ extern declarations
# ══════════════════════════════════════════════════════════════════════════════
mkdir -p build/res
ln -sf "$SF_SRC"   build/res/fairy-stockfish
ln -sf "$NNUE_SRC" build/res/nn-46832cfbead3.nnue.xz
ln -sf "$ICON_SRC" build/res/cipherlogo.png

# ── Step 1: Embed resources with objcopy ──────────────────────────────────────
echo ""
step "[1/4] Embedding resources with objcopy ..."

(
  cd build
  objcopy \
      --input-target binary \
      --output-target elf64-x86-64 \
      --binary-architecture i386:x86-64 \
      res/fairy-stockfish \
      stockfish.o

  objcopy \
      --input-target binary \
      --output-target elf64-x86-64 \
      --binary-architecture i386:x86-64 \
      res/nn-46832cfbead3.nnue.xz \
      nnue.o

  objcopy \
      --input-target binary \
      --output-target elf64-x86-64 \
      --binary-architecture i386:x86-64 \
      res/cipherlogo.png \
      icon.o
)

ok "Resources embedded into object files"

# ── Step 2: Compile ───────────────────────────────────────────────────────────
echo ""
step "[2/4] Compiling cipher_launcher_linux.cpp ..."

g++ \
    -std=c++17 \
    -O3 \
    -flto \
    -fvisibility=hidden \
    -ffunction-sections \
    -fdata-sections \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -Wall \
    -Wextra \
    -Wno-unused-result \
    -pthread \
    src/cipher_launcher_linux.cpp \
    build/stockfish.o \
    build/nnue.o \
    build/icon.o \
    -Wl,--gc-sections \
    -Wl,-z,relro \
    -Wl,-z,now \
    -Wl,-z,noexecstack \
    -Wl,--strip-all \
    -o CipherLauncher

ok "CipherLauncher compiled"

# ── Step 3: Strip symbols ─────────────────────────────────────────────────────
echo ""
step "[3/4] Stripping debug symbols and build metadata ..."

# --strip-all removes all symbols; --remove-section strips build-id and comment
# sections that leak compiler version, build path, and timestamp info
strip \
    --strip-all \
    --remove-section=.comment \
    --remove-section=.note \
    --remove-section=.note.ABI-tag \
    --remove-section=.note.gnu.build-id \
    --remove-section=.gnu_debuglink \
    CipherLauncher

ok "Symbols and metadata sections stripped"

# ── Step 4: Pack with UPX (optional) ─────────────────────────────────────────
echo ""
if [[ $UPX_AVAILABLE -eq 1 ]]; then
    step "[4/4] Packing with UPX ..."
    upx --best --lzma CipherLauncher
    ok "UPX packing done"
else
    step "[4/4] Skipping UPX (not installed) ..."
    warn "Install upx for an additional obfuscation layer: sudo apt install upx"
fi

# ── Final report ──────────────────────────────────────────────────────────────
echo ""
SIZE=$(du -sh CipherLauncher | cut -f1)
echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}"
echo    "   Build successful!"
echo    "   Output: CipherLauncher  ($SIZE)"
echo    ""
echo    "   Distribute ONLY CipherLauncher — nothing else needed."
echo    "   Users run:  chmod +x CipherLauncher && ./CipherLauncher"
echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}\n"