# Cipher Engine Launcher v2.0 — Linux Build

## What this is

A port of `CipherLauncher.exe` to Linux. It embeds Fairy-Stockfish and the
NNUE weights directly inside the binary — users just run one file.

---

## Step 1 — Copy your resource files into `res/`

Open WSL and run these two commands, pointing to your actual file locations:

```bash
# Linux Fairy-Stockfish binary
cp "/mnt/c/Users/algorithm/Downloads/fairy-stockfish-largeboard_x86-64-modern" res/fairy-stockfish

# NNUE weights (already compressed — just copy the .xz as-is)
cp "/mnt/c/Users/algorithm/Downloads/cipher_v2/cipher_project/res/nn-46832cfbead3.nnue.xz" res/
```

## Step 2 — Build

```bash
bash build.sh
```

This compiles everything. Output: **`CipherLauncher`** — a single self-contained
binary with the engine and NNUE baked in.

> **Requirements** (all pre-installed in Ubuntu/Debian WSL):
> ```bash
> sudo apt install build-essential binutils xz-utils
> ```

---

## What the output binary does

When a user runs `CipherLauncher`:

1. **First run** — extracts `fairy-stockfish` and decompresses the NNUE into
   `~/.cipher/` using the system `xz` utility
2. **Starts a WebSocket server** on `ws://localhost:8765` using the same UCI
   protocol as the Windows version — fully compatible with the Cipher Chrome
   extension
3. **Subsequent runs** — skips extraction, starts the engine immediately

---

## Distribute

Send users **only `CipherLauncher`**. No other files needed.

```bash
chmod +x CipherLauncher
./CipherLauncher
```

Or run it in the background (auto-start on login via `~/.bashrc`):
```bash
./CipherLauncher &
```
