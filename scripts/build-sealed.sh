#!/usr/bin/env bash
# Builds sealed/ (sealed-sender unwrap on libsignal-protocol, pinned to a libsignal release tag)
# to WASM and writes JS bindings to src/vendor/signal-sealed/.
# Cargo fetches github.com/signalapp/libsignal at the tag in sealed/Cargo.toml and runs its build
# scripts. Needs the same toolchain as build-tls.sh (rustup wasm32 target, LLVM clang,
# wasm-bindgen-cli 0.2.130), plus protoc (brew install protobuf / apt-get install protobuf-compiler).
# On Linux the system clang and llvm-ar are used when Homebrew's LLVM isn't there.
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
# These flags replace the ones in sealed/.cargo/config.toml, so its getrandom cfg is repeated here.
(cd sealed && CARGO_ENCODED_RUSTFLAGS="$(encode --cfg 'getrandom_backend="wasm_js"' "${remap[@]}")" \
  cargo build --release --target wasm32-unknown-unknown)
wasm-bindgen --target web --out-dir src/vendor/signal-sealed \
  sealed/target/wasm32-unknown-unknown/release/signal_sealed.wasm
ls -l src/vendor/signal-sealed
