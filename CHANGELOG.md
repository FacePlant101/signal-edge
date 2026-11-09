# Changelog

signal-edge follows [semantic versioning](https://semver.org) for 0.x: a breaking change bumps the minor version.

## 0.2.0

First release on npm.

- **Node.js** (22.13 or later): `signal-edge/node` configures TCP (`node:net`) and the WASM modules itself, and adds `nodeSqlite()` (a file path, or an open node:sqlite or better-sqlite3 database; WAL mode, nested transactions) and `createNodeClient()`, which runs maintenance on a timer and has `shutdown()`. `examples/node` is a small CLI (link, status, listen, send).
- CI talks to Signal's servers on every run, without an account: pinned TLS to chat.signal.org, a public-CA host refused, and the provisioning socket (`test/network.test.mjs`, `SIGNAL_NETWORK_TESTS=1`).
- `crypto.ts` no longer names a Workers-only type, so the code typechecks under Node's types too.

### Security (from a review before the first release)

- Attachment and long-text downloads are capped by what is actually read, not by the size the sender claims, and a timed-out download is cancelled. `downloadAttachment(pointer, size, { maxBytes, signal })`; `signalFetch` takes `maxBytes` (default 16 MiB), `timeoutMs` (default 60 s) and `signal`.
- Group messages from senders who aren't members are dropped, as in Signal's apps; the sealed-sender group id no longer routes messages. Groups named by unknown master keys are stored only once the server confirms we're a member, and refetches are throttled.
- The safety-number check covers identity keys with bytes appended (libsignal ignores the extra bytes), and PreKey messages from our own account must carry our own identity key.
- TLS: bytes after the peer's close_notify no longer make the client loop forever.
- `reset()` stops work started for the forgotten account (sockets, handlers, syncs, key refresh, linking) from writing anything back.
- Timeouts on the TLS handshake, every HTTP request and the WebSocket upgrade; a WebSocket that stops answering keepalives is closed and reconnected; reassembled WebSocket messages are capped.
- The phone number is no longer stored outside the sealed account secrets; `nodeSqlite` creates its file with mode 0600; the README says which metadata is stored unencrypted.
- Quotes are checked against the stored message (`quote.verified`); a later message can't rewrite an earlier one through long-text expansion; sender keys per device and undecryptable envelopes are capped; CDN redirects go to public https hosts only; the self-tests refuse a database with an account.
- CI: the WASM build runs with a read-only token (attesting and committing are separate jobs), and releases are verified and packed without publishing rights, from tagged commits on main only.

## 0.1.0

Extracted from a private Cloudflare Workers app, which has used it since 2026-11-09; installed from GitHub, never published to npm.

- `SignalClient`: linking, the receive loop (sealed sender, sender keys, sync transcripts, long texts), sending (1:1 and groups, sealed sender, sender-key group sends, attachments, quotes, reactions, mentions, disappearing-message timers), contacts and groups, retry requests, prekey maintenance, counters that survive restarts.
- `signal-edge/workers`: Cloudflare Workers and Durable Objects (`durableObjectHost`, `durableObjectSql`).
- `signal-edge/selftest`: network-free self-tests.
- Credits in NOTICE and README; THIRD_PARTY_LICENSES.txt for the prebuilt WASM.
