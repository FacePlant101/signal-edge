# Changelog

signal-edge follows [semantic versioning](https://semver.org) for 0.x: a breaking change bumps the minor version.

## Unreleased

- **Standalone registration**: a phone number can be registered as a new account with this device as its primary, no phone app needed, following Signal-Desktop's standalone registration (nightly builds): `startRegistration(number)` → `submitCaptcha(token)` → `requestCode("sms" | "voice")` → `verifyCode(code)`. The account gets new identity keys, registration ids, profile key and account entropy pool (with its registration recovery password). `status()` reports `{ state: "registering", step }` meanwhile and `primary: true` once registered. No PIN or registration lock yet (SVR2 needs SGX attestation). The REST calls are exported too (`createVerificationSession`, `submitCaptcha`, `requestVerificationCode`, `submitVerificationCode`, `registerAccount`).
- A primary account without linked devices sends no sync transcripts (checked with `GET /v1/devices`), and `notifySelf()` refuses, since no other device would show it. `notifyContact(aci, body)` sends such one-time messages to a contact instead (not stored, logged or synced).

## 0.2.0

First release on npm.

- **Node.js** (22.13 or later): `signal-edge/node` configures TCP (`node:net`) and the WASM modules itself, and adds `nodeSqlite()` (a file path, or an open node:sqlite or better-sqlite3 database; WAL mode, nested transactions) and `createNodeClient()`, which runs maintenance on a timer and has `shutdown()`. `examples/node` is a small CLI (link, status, listen, send).
- CI talks to Signal's servers on every run, without an account: pinned TLS to chat.signal.org, a public-CA host refused, and the provisioning socket (`test/network.test.mjs`, `SIGNAL_NETWORK_TESTS=1`).
- `crypto.ts` no longer names a Workers-only type, so the code typechecks under Node's types too.

### Security (from a review before the first release)

- Attachment and long-text downloads are capped by what is actually read, not by the size the sender claims, and a timed-out download is cancelled. `downloadAttachment(pointer, size, { maxBytes, signal, timeoutMs })` (default 10 minutes for the whole download); `signalFetch` takes `maxBytes` (default 16 MiB), `timeoutMs` (default 60 s) and `signal`.
- Group messages from senders who aren't members are dropped, as in Signal's apps; the sealed-sender group id no longer routes messages. A sender missing from the stored member list makes us ask the groups server (at most once a minute per group and sender), so someone just added isn't dropped; only the server's 403/404 counts as "not a member", and messages are kept while the server can't be reached. Groups named by unknown master keys (in records or in a bare group context) are fetched within hourly budgets (per sender; past the overall budget, messages are kept unchecked) and stored only once the server confirms we're a member.
- The safety-number check covers identity keys with bytes appended (libsignal ignores the extra bytes), and PreKey messages from our own account must carry our own identity key.
- TLS: bytes after the peer's close_notify no longer make the client loop forever.
- `reset()` stops work started for the forgotten account (sockets, handlers, sends, syncs, key refresh, linking) from writing anything back: the database view that work holds refuses it (`AccountForgotten`), and sends in progress are aborted.
- Timeouts on the TLS handshake, every HTTP request (`fetch()` to CDNs included) and the WebSocket upgrade; a WebSocket that stops answering keepalives (while no request is being handled) is closed and reconnected, and closing a socket doesn't wait on a stalled write; reassembled WebSocket messages are capped.
- The phone number is no longer stored outside the sealed account secrets (`status().number` comes back once they are read); `nodeSqlite` creates its file with mode 0600; the README says which metadata is stored unencrypted.
- Quotes are checked against the stored message by id and author (`quote.verified`; text and mentions then come from the stored message); a later message can't rewrite an earlier one through long-text expansion; other people's sender keys per device (256, least recently used go first, in the database and in memory; our own aren't capped) and undecryptable envelopes are capped; CDN redirects go to public https hosts only; the self-tests refuse a database with an account.
- CI: the WASM build runs with a read-only token (attesting and committing are separate jobs), and releases are verified and packed without publishing rights, from tagged commits on main only.

## 0.1.0

Extracted from a private Cloudflare Workers app, which has used it since 2026-11-09; installed from GitHub, never published to npm.

- `SignalClient`: linking, the receive loop (sealed sender, sender keys, sync transcripts, long texts), sending (1:1 and groups, sealed sender, sender-key group sends, attachments, quotes, reactions, mentions, disappearing-message timers), contacts and groups, retry requests, prekey maintenance, counters that survive restarts.
- `signal-edge/workers`: Cloudflare Workers and Durable Objects (`durableObjectHost`, `durableObjectSql`).
- `signal-edge/selftest`: network-free self-tests.
- Credits in NOTICE and README; THIRD_PARTY_LICENSES.txt for the prebuilt WASM.
