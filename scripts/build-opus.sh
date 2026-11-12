#!/usr/bin/env bash
# Builds opus/ (libopus for calls) to WASM and writes JS bindings to src/vendor/signal-opus/.
# libopus is fetched from Xiph's repository at a pinned tag and checked against its commit id (as
# sealed/ pins libsignal), into opus/libopus (not committed). Same toolchain as build-tls.sh: rustup
# with the wasm32 target, LLVM clang and llvm-ar, wasm-bindgen-cli 0.2.130.
set -euo pipefail
cd "$(dirname "$0")/.."

OPUS_TAG=v1.5.2
OPUS_COMMIT=ddbe48383984d56acd9e1ab6a090c54ca6b735a6

if [ "$(git -C opus/libopus rev-parse HEAD 2>/dev/null || true)" != "$OPUS_COMMIT" ]; then
  rm -rf opus/libopus
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$OPUS_TAG" https://github.com/xiph/opus.git opus/libopus
fi
got="$(git -C opus/libopus rev-parse HEAD)"
[ "$got" = "$OPUS_COMMIT" ] || { echo "libopus $OPUS_TAG is $got, expected $OPUS_COMMIT" >&2; exit 1; }

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
LLVM="$(brew --prefix llvm 2>/dev/null || echo /opt/homebrew/opt/llvm)/bin"
if [ ! -x "$LLVM/clang" ]; then
  CLANG="$(command -v clang)" || { echo "clang not found (install LLVM)" >&2; exit 1; }
  LLVM="$(dirname "$CLANG")"
fi
[ -x "$LLVM/llvm-ar" ] || { echo "llvm-ar not found next to $LLVM/clang (install llvm)" >&2; exit 1; }
export CC_wasm32_unknown_unknown="$LLVM/clang" AR_wasm32_unknown_unknown="$LLVM/llvm-ar"

# No local paths in the output (see build-sealed.sh).
remap=(--remap-path-prefix="$HOME/.cargo=/cargo" --remap-path-prefix="$PWD=/signal-edge")
export CFLAGS_wasm32_unknown_unknown="-ffile-prefix-map=$HOME/.cargo=/cargo -ffile-prefix-map=$PWD=/signal-edge"
encode() { local IFS=$'\x1f'; echo "$*"; }
(cd opus && CARGO_ENCODED_RUSTFLAGS="$(encode "${remap[@]}")" cargo build --locked --release --target wasm32-unknown-unknown)
wasm-bindgen --target web --out-dir src/vendor/signal-opus \
  opus/target/wasm32-unknown-unknown/release/signal_opus.wasm
ls -l src/vendor/signal-opus
