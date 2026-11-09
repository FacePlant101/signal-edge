#!/usr/bin/env bash
# Builds tls/ (rustls pinned to Signal's roots) to WASM and writes JS bindings to src/vendor/signal-tls/.
# Needs: rustup with the wasm32-unknown-unknown target, LLVM clang and llvm-ar (brew install llvm, or the
# system ones on Linux) for ring's C code,
# and wasm-bindgen-cli at the exact version pinned in tls/Cargo.toml.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
LLVM="$(brew --prefix llvm 2>/dev/null || echo /opt/homebrew/opt/llvm)/bin"
if [ ! -x "$LLVM/clang" ]; then
  CLANG="$(command -v clang)" || { echo "clang not found (install LLVM)" >&2; exit 1; }
  LLVM="$(dirname "$CLANG")"
fi
[ -x "$LLVM/llvm-ar" ] || { echo "llvm-ar not found next to $LLVM/clang (install llvm)" >&2; exit 1; }
export CC_wasm32_unknown_unknown="$LLVM/clang" AR_wasm32_unknown_unknown="$LLVM/llvm-ar"

# Panic messages carry source paths: map the home directory and this checkout to fixed names, so the
# binary names neither (and builds on different machines match more closely).
remap=(--remap-path-prefix="$HOME/.cargo=/cargo" --remap-path-prefix="$PWD=/signal-edge")
export CFLAGS_wasm32_unknown_unknown="-ffile-prefix-map=$HOME/.cargo=/cargo -ffile-prefix-map=$PWD=/signal-edge"
encode() { local IFS=$'\x1f'; echo "$*"; }
CARGO_ENCODED_RUSTFLAGS="$(encode "${remap[@]}")" \
  cargo build --locked --manifest-path tls/Cargo.toml --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir src/vendor/signal-tls \
  tls/target/wasm32-unknown-unknown/release/signal_tls.wasm
ls -l src/vendor/signal-tls
