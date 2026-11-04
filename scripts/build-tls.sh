#!/usr/bin/env bash
# Builds tls/ (rustls pinned to Signal's roots) to WASM and writes JS bindings to src/vendor/signal-tls/.
# Needs: rustup with the wasm32-unknown-unknown target, LLVM clang (brew install llvm) for ring's C code,
# and wasm-bindgen-cli at the exact version pinned in tls/Cargo.toml.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
LLVM="$(brew --prefix llvm 2>/dev/null || echo /opt/homebrew/opt/llvm)/bin"
export CC_wasm32_unknown_unknown="$LLVM/clang" AR_wasm32_unknown_unknown="$LLVM/llvm-ar"

cargo build --manifest-path tls/Cargo.toml --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir src/vendor/signal-tls \
  tls/target/wasm32-unknown-unknown/release/signal_tls.wasm
ls -l src/vendor/signal-tls
