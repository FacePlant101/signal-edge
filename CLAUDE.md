# CLAUDE.md: context for working on signal-edge

A Signal linked-device client library, Workers first, runtime-pluggable. Extracted on 2026-11-04 from FacePlant101/signal-mcp-worker (commit 44c0674), which is its main user and the place where things get verified against a real account. See README.md for the layers and API.

## Layout
- `src/client.ts` `SignalClient`: the account (linking, receive loop, sending, directory, retries, keys). No host APIs: storage is `SqlDatabase` (src/sql.ts); background work, scheduling and new-message notification are options (`waitUntil`, `scheduleMaintenance`, `onMessages`).
- `src/runtime.ts`: `configure({ connect, wasm, userAgent })`. `src/workers.ts` (`signal-edge/workers`) configures `cloudflare:sockets` and the `.wasm` imports, and adds `durableObjectSql`/`durableObjectHost`. **Only workers.ts may import `cloudflare:*` or `.wasm` files**; the core must load in Node (the tests prove it).
- `src/protocol/*`: Signal protocol pieces; `src/net/*`: TLS socket, HTTP/1.1, WebSocket; `src/selftest/*` (`signal-edge/selftest`): network-free self-tests.
- `tls/`, `sealed/`: Rust crates built to `src/vendor/` (checked in). `scripts/copy-vendor.mjs` copies them into `dist/`.
- `examples/worker`: minimal Durable Object app; `npm run check` bundles it with Wrangler (dry run).

## Rules
- **Compatibility with existing data:** table names, columns, kv keys and Sealer AAD labels (`account_secrets`, `sender_certificate|aci.device`, `table|identity|key`, …) must stay as they are, or signal-mcp-worker's linked account stops working. Add migrations, don't rename.
- Relative imports end in `.js` (module `nodenext`); the build is plain `tsc`.
- Anything talking to Signal goes through `signalFetch`/`SignalSocket` (pinned TLS), never `fetch()`, except CDN redirects to non-signal.org hosts.
- Run `npm run typecheck` and `npm test` before committing; after changing `tls/` or `sealed/`, rebuild (`npm run build:tls` / `build:sealed`) and commit `src/vendor/`.
- No key material, account data or real phone numbers in tests or fixtures. Live tests only with a throwaway number.
- AGPL-3.0-only (libsignal).

## Gotchas (from the signal-mcp-worker spike, still true)
- wasm-bindgen objects may be consumed when passed by value: create a fresh `WasmProtocolAddress` per call.
- signal-wasm 0.6.6 reports every libsignal failure as `SignalError: Operation failed`; test behaviour, not error text. Its `WasmInMemIdentityKeyStore` can't be exported and rejects a changed key it has cached, hence our `identities` table and `ProtocolStore.resetIdentityStore()`.
- Kyber one-time keys must be tombstoned after use (`afterDecrypt`), and `export_kyber_usage`/`import_kyber_usage` carries the anti-replay set.
- `chat.signal.org`, `storage.signal.org` and the CDNs present Signal-CA certificates (Ed25519 leaf, TLS 1.3); `fetch()` on Workers returns 526.
- On the deployed edge a single `cloudflare:sockets` write above 64 KiB kills the connection; `net/tls.ts` writes at most 16 KiB through one ordered queue. Local workerd doesn't reproduce this.
- A server may answer and close before reading a large body; `signalFetch` still reads the response after a failed write.
- Durable Object outbound WebSockets don't hibernate (they keep the object alive).
- This sandbox's network proxy blocks raw TCP, so the example's `/link` can't reach Signal from a cloud session; network paths are verified by deploying (signal-mcp-worker).
- getrandom 0.2/0.3/0.4 in `sealed/` each need their JS backend feature (see sealed/Cargo.toml and .cargo/config.toml).
