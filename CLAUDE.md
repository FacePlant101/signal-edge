# CLAUDE.md: context for working on signal-edge

A Signal linked-device client library, Workers first, runtime-pluggable. Extracted from the owner's private Workers app (synced on 2026-11-08), which is its main user and the place where things get verified against a real account. That app is private: don't name it or link to it in this repository (docs, code, commit messages). See README.md for the layers and API.

## Layout
- `src/client.ts` `SignalClient`: the account (linking, receive loop, sending, directory, retries, keys). No host APIs: storage is `SqlDatabase` (src/sql.ts); background work, scheduling and new-message notification are options (`waitUntil`, `scheduleMaintenance`, `onMessages`).
- `src/runtime.ts`: `configure({ connect, wasm, userAgent })`. `src/workers.ts` (`signal-edge/workers`) configures `cloudflare:sockets` and the `.wasm` imports, and adds `durableObjectSql`/`durableObjectHost`. **Only workers.ts may import `cloudflare:*` or `.wasm` files**; the core must load in Node (the tests prove it).
- `src/node.ts` (`signal-edge/node`, Node ≥ 22.13): `nodeConnect` (`net.connect` + `Duplex.toWeb`), WASM compiled from the package's files at import, `nodeSqlite` (path → node:sqlite in WAL mode, or an open node:sqlite/better-sqlite3 db; savepoint transactions), `createNodeClient` (maintenance on a timer, `shutdown()`). It is built in a second tsc pass (`tsconfig.node.json`, Node + DOM types, output via `dist-node/`) and imports the core as `"signal-edge"` (package self-reference), so the core is typechecked once, with Workers types; under DOM types the core has ~30 Uint8Array/BufferSource errors that don't matter at runtime.
- Tests: `npm test` (Node). `test/network.test.mjs` connects to Signal (pinned TLS, provisioning socket) only with `SIGNAL_NETWORK_TESTS=1`; CI sets it. Cloud sessions can't run it (no DNS/raw TCP egress).
- Releases: version + CHANGELOG.md in a PR, then tag `v<version>`; `.github/workflows/release.yml` publishes to npm (trusted publishing/OIDC, or the `NPM_TOKEN` secret until that is set up). `prepublishOnly` runs typecheck and tests.
- `src/protocol/*`: Signal protocol pieces; `src/net/*`: TLS socket, HTTP/1.1, WebSocket; `src/selftest/*` (`signal-edge/selftest`): network-free self-tests.
- `tls/`, `sealed/`: Rust crates built to `src/vendor/` (checked in). `scripts/copy-vendor.mjs` copies them into `dist/`.
- `examples/worker`: minimal Durable Object app; `npm run check` bundles it with Wrangler (dry run).

## Rules
- **Compatibility with existing data:** table names, columns, kv keys and Sealer AAD labels (`account_secrets`, `sender_certificate|aci.device`, `table|identity|key`, …) must stay as they are, or existing deployments' linked accounts stop working. Add migrations, don't rename.
- Relative imports end in `.js` (module `nodenext`); the build is plain `tsc`.
- Anything talking to Signal goes through `signalFetch`/`SignalSocket` (pinned TLS), never `fetch()`, except CDN redirects to non-signal.org hosts.
- Run `npm run typecheck` and `npm test` before committing. `src/vendor/` must be exactly what `.github/workflows/wasm.yml` builds (reproducible: `rust-toolchain.toml`, wasm-bindgen-cli 0.2.130, Ubuntu 24.04 clang 18, paths remapped by the build scripts); after changing `tls/` or `sealed/`, rebuild with that toolchain or run the workflow with `commit=true`, and never commit binaries built any other way.
- Commit messages, PR titles and PR descriptions never contain session links or "Generated with Claude Code" footers (owner's rule).
- No key material, account data or real phone numbers in tests or fixtures. Live tests only with a throwaway number.
- AGPL-3.0-only (libsignal). Credits live in NOTICE and README "Credits"; after any `Cargo.lock` change, run `python3 scripts/third-party-licenses.py` and commit `THIRD_PARTY_LICENSES.txt` (it ships with the prebuilt WASM).

## Security rules (from the review before 0.2.0)
- Everything in a message is the sender's word: sizes in attachment pointers, quoted text, group context. Downloads are capped by bytes read (`downloadAttachment` `maxBytes`, `signalFetch` `maxBytes`); group records need the sender to be a member (`SignalClient.#dropNonMembers`); quotes are checked against stored messages.
- Every network call has a deadline (`signalFetch` `timeoutMs`, TLS handshake, WebSocket upgrade); a call without one can hold the protocol lock forever.
- Background work captures `#generation` and checks it (`#stillCurrent`) right before writing (no await in between); `reset()` bumps it. Stores and helpers are built on `#accountDb`, a view bound to the generation that refuses work once a reset has moved on (`AccountForgotten`); take them before the first network call. New background paths must do the same.
- `tls/` has host tests (`cargo test --manifest-path tls/Cargo.toml --target x86_64-unknown-linux-gnu`), run by the WASM workflow; test/security.test.mjs covers the rest.

## Gotchas (from the original spike, still true)
- wasm-bindgen objects may be consumed when passed by value: create a fresh `WasmProtocolAddress` per call.
- Workers-only APIs (`crypto.subtle.timingSafeEqual`, …) don't belong in the core; use the helpers in `src/util/bytes.ts`. `npm test` runs the core in Node and catches them.
- signal-wasm 0.6.6 reports every libsignal failure as `SignalError: Operation failed`; test behaviour, not error text. Its `WasmInMemIdentityKeyStore` can't be exported and rejects a changed key it has cached, hence our `identities` table and `ProtocolStore.resetIdentityStore()`.
- Kyber one-time keys must be tombstoned after use (`afterDecrypt`), and `export_kyber_usage`/`import_kyber_usage` carries the anti-replay set.
- `chat.signal.org`, `storage.signal.org` and the CDNs present Signal-CA certificates (Ed25519 leaf, TLS 1.3); `fetch()` on Workers returns 526.
- On the deployed edge a single `cloudflare:sockets` write above 64 KiB kills the connection; `net/tls.ts` writes at most 16 KiB through one ordered queue. Local workerd doesn't reproduce this.
- A server may answer and close before reading a large body; `signalFetch` still reads the response after a failed write.
- Durable Object outbound WebSockets don't hibernate (they keep the object alive).
- This sandbox's network proxy blocks raw TCP, so the example's `/link` can't reach Signal from a cloud session; network paths are verified by CI's network tests and by deploying the app that uses the library.
- getrandom 0.2/0.3/0.4 in `sealed/` each need their JS backend feature (see sealed/Cargo.toml and .cargo/config.toml).
