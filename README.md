# signal-edge

A Signal client that runs as a **linked device** (like Signal Desktop) inside Cloudflare Workers, or any JavaScript runtime that can open a TCP socket and run WebAssembly. It links to an existing Signal account with a QR code, keeps a live connection to Signal, decrypts what arrives, and sends 1:1 and group messages with attachments, quotes, reactions and mentions. No signal-cli, JVM, container or VPS.

> **Unofficial.** This is not Signal's software, Signal doesn't support it, and it can break whenever Signal changes its servers. Try it with a spare number first. It handles real end-to-end-encrypted traffic and stores keys that can read it: treat the storage key like a password.

Extracted from [signal-mcp-worker](https://github.com/FacePlant101/signal-mcp-worker) (as of its PR #16), where it runs against a real account.

## What works

| Area | Status |
|---|---|
| Linking (provisioning socket, QR code, `PUT /v1/devices/link`) | verified on a real account |
| Receive loop (authenticated WebSocket, sealed sender, 1:1, groups via sender keys, sync transcripts, receipts, typing) | verified on a real account |
| Prekeys (one-time, Kyber, signed, last resort; refill and rotation like Desktop) | verified on a real account |
| 1:1 and group text sends, sync transcripts to your other devices | verified on a real account |
| Contacts and groups (storage service, zkgroup credentials, group state) | verified on a real account |
| Attachment download and decryption, long received texts | verified on a real account |
| Safety-number changes (accepted like the apps do, recorded in the chat) | verified on Workers (self-test) |
| Sealed-sender sends, retry requests (resend after a failed decrypt) | self-test only; not yet seen by a real recipient |
| Sending attachments and long texts (long-text attachment past 2000 bytes) | deployed; not yet seen by a real recipient |
| Sender-key group sends (`multi_recipient`, group send endorsements; falls back to one copy per member) | deployed; not yet run in a group of 3+ |
| Disappearing-message timers, quoted replies, reactions, mentions | built; not yet seen on real clients |
| Counters and last errors that survive restarts | built |

Not there yet: phone-number lookup (CDSI needs SGX attestation, so recipients are ACIs), delivery/read receipts, stories, calls, registering a new primary account.

## How it works

```
SignalClient            linking, receive loop, send, contacts/groups, keys, retries
  protocol/             envelopes, Content, sender, receiver, stores, groups, storage service
    signal-wasm         libsignal sessions, ratchet, prekeys, sender keys  (@getmaapp/signal-wasm)
    sealed/ (Rust)      sealed sender seal/unseal, zkgroup, access keys    (libsignal v0.106.1)
  net/                  HTTP/1.1, WebSocket, TLS socket
    tls/ (Rust)         TLS 1.3 (rustls + ring) trusting only Signal's two roots
  runtime               connect(host, port) → raw TCP; the three WASM modules
  SqlDatabase           synchronous SQLite: Durable Object storage, node:sqlite, …
```

Signal's servers present certificates from Signal's own root CA. `fetch()` on Workers can't verify that (you get HTTP 526), so the library opens a plain TCP socket and runs TLS itself in WebAssembly, pinned to Signal's two root certificates, as libsignal does. WebSockets and HTTP are framed on top of that.

Everything the client stores (sessions, keys, messages, contacts) is encrypted with AES-256-GCM under your storage key. Each row's location is bound into the encryption, so a row copied elsewhere won't decrypt.

## Install

From GitHub (the `prepare` script builds `dist/`):

```sh
npm install github:FacePlant101/signal-edge
```

The WebAssembly is prebuilt and checked in (`src/vendor/`), so you don't need Rust unless you change `tls/` or `sealed/`.

## Cloudflare Workers

Import from `signal-edge/workers`. That entry point sets up `cloudflare:sockets` and the WASM modules (Wrangler bundles `.wasm` imports). Keep one `SignalClient` per account inside a SQLite-backed Durable Object:

```ts
import { DurableObject } from "cloudflare:workers";
import { durableObjectHost, SignalClient } from "signal-edge/workers";

export class SignalAccount extends DurableObject<Env> {
	client = new SignalClient({
		...durableObjectHost(this.ctx), // SQLite, waitUntil, maintenance via the alarm
		storageKey: this.env.STORAGE_KEY, // 32 random bytes, base64
		deviceName: "My bot",
		onMessages: (records) => {
			/* new incoming or synced records */
		},
	});

	async alarm() {
		const next = await this.client.maintain(); // reconnect, prekeys, contacts
		if (next) await this.ctx.storage.setAlarm(next);
	}

	// RPC methods for your Worker (a SignalClient can't cross the stub boundary itself)
	link() { return this.client.startLink(); } // { state: "waiting_for_scan", url: "sgnl://linkdevice?…" } → show as QR
	status() { return this.client.status(); } // … { state: "linked", aci, deviceId, … }
	send(to: string, body: string) { return this.client.sendText(to, body); }
}
```

Then from your Worker: `await env.ACCOUNT.getByName("primary").send("self", "hello from the edge")`.

[`examples/worker`](examples/worker) is a complete version with routes to link, read, send and run the self-tests. Run it with `npm install && npx wrangler dev` (put `ADMIN_TOKEN` and `STORAGE_KEY` in `.dev.vars`).

Things to know on Workers:

- A Durable Object's outbound WebSocket doesn't hibernate, so it keeps the object running. One always-on object comes to about 324k GB-s a month, under the Workers Paid plan's 400k included.
- On the deployed edge, a single socket write over 64 KiB drops the connection. The TLS layer writes at most 16 KiB at a time.
- After a deploy, a Durable Object that stays busy keeps running the old code for up to 5 minutes. To switch at once, deploy with `wrangler versions deploy <id>@100% --durable-objects-code-update-mode immediate`.
- Signal removes linked devices that stay offline for about 30 days. The receive loop keeps the device active as long as the alarm runs.

## Other runtimes

The core (`signal-edge`) uses only web-standard APIs (WebCrypto, streams, `fetch` for CDN redirects). Give it a socket and the WASM:

```ts
import { configure, SignalClient } from "signal-edge";

configure({
	connect: (hostname, port) => myTcpConnect(hostname, port), // { readable, writable, opened, close() }
	wasm: { signal: signalWasmModule, sealed: sealedWasmModule, tls: tlsWasmModule }, // WebAssembly.Module or bytes
});
const client = new SignalClient({ db: mySqliteAdapter, storageKey, scheduleMaintenance: (at) => setTimer(at) });
```

The WASM files are `@getmaapp/signal-wasm/signal_wasm_bg.wasm`, `signal-edge/wasm/signal-sealed/signal_sealed_bg.wasm` and `signal-edge/wasm/signal-tls/signal_tls_bg.wasm`. `SqlDatabase` is two methods, `exec(query, ...bindings) → rows` and `transaction(fn)`. [`test/node-host.mjs`](test/node-host.mjs) adapts `node:sqlite` in about 30 lines. The tests run the whole crypto and storage stack in Node this way. A Node TCP adapter (`node:net` to web streams) isn't included yet.

## API

`SignalClient`:

| Method | What |
|---|---|
| `status()`, `self()` | link state; our ACI/PNI/device once linked |
| `startLink()` | opens the provisioning socket, returns the `sgnl://linkdevice` URL; linking finishes in the background (`waitUntil`) |
| `maintain()` | watchdog: (re)connects the receive socket, prunes retry state, refreshes prekeys and contacts when due; returns when to run next |
| `startReceiving()`, `stopReceiving()`, `receiveStatus()` | the receive socket and its counters |
| `sendText(to, body, files?, extras?)` | `to` = `"self"`, `aci:<uuid>` or `group:<id>`; `files` = forwarded attachments (`{ref}`), text or base64; `extras` = `replyTo` / `reaction` by a stored message's sentAt; `@[aci:<uuid>]` in group text is a mention. Returns devices reached, sealed-sender and sender-key use, sync result, safety-number changes |
| `notifySelf(body)` | Note to Self that isn't stored or logged (for one-time codes) |
| `messages(limit, chat?)`, `conversations()`, `chats()` | stored history; chats include known groups and contact names |
| `syncDirectory()`, `contacts()`, `groups()`, `group(id, refresh?)`, `names()` | contacts and groups (no keys in the output) |
| `attachment(messageId, index, maxBytes?)` | downloads and decrypts an attachment of a stored message |
| `refreshKeys(force?)`, `keyStatus()`, `whoami()` | prekey maintenance and a credentials check |
| `reset()` | forgets the account locally (empties `SIGNAL_TABLES`) |
| `messageStore()`, `directory()` | lower-level stores |

The building blocks are exported too (`signalFetch`, `SignalSocket`, `ProtocolStore`, `receiveEnvelope`, `sendToServiceId`, `readStorage`, `fetchGroupState`, `unseal`, `decryptAttachment`, …), for anyone who wants to drive the protocol themselves. `signal-edge/selftest` has three self-tests that need no network: link crypto, store persistence, and the receive path (sealed sender, sender keys, identity changes, retry requests).

## Storage

The client owns these tables (`SIGNAL_TABLES`): `kv`, `failed_envelopes`, `prekeys`, `signed_prekeys`, `kyber_prekeys`, `kyber_usage`, `sessions`, `sender_keys`, `key_counters`, `messages`, `groups`, `contacts`, `send_log`, `seen_envelopes`, `chat_timers`, `sender_key_shares`, `counters`, `last_errors`, `identities`. Your app can keep its own tables in the same database. Don't reuse these names, except to add your own keys to `kv`. Table names, column layouts and encryption labels are kept compatible with signal-mcp-worker, so an account linked there keeps working.

## Development

```sh
npm install        # also builds dist/
npm run typecheck
npm test           # builds, then runs the self-tests and client tests in Node 22 (node:sqlite)
cd examples/worker && npm install && npm run check   # typecheck + wrangler bundle (dry run)
```

Rebuilding the WASM (only after changing `tls/` or `sealed/`) needs rustup with the `wasm32-unknown-unknown` target, LLVM clang and llvm-ar, `wasm-bindgen-cli` 0.2.130, and `protoc` for `sealed/`. Then run `npm run build:tls` / `npm run build:sealed` and commit `src/vendor/`. After a change to either `Cargo.lock`, regenerate the license notices with `python3 scripts/third-party-licenses.py` and commit `THIRD_PARTY_LICENSES.txt`.

## Credits

signal-edge stands on Signal's own work. Thanks to:

- **[Signal Messenger](https://signal.org)**: [Signal-Desktop](https://github.com/signalapp/Signal-Desktop), whose linking, sending, receiving, groups and storage-service code this library follows and in places ports (each source file names the Desktop functions it follows), and [libsignal](https://github.com/signalapp/libsignal), whose Rust crates `sealed/` is built on and whose root certificates `tls/` pins. [Signal-Android](https://github.com/signalapp/Signal-Android) was a reference for timer behaviour.
- **[signal-wasm](https://github.com/getmaapp/signal-wasm)** by getmaapp: libsignal compiled to WebAssembly. It made a Worker-native client possible.
- **[rustls](https://github.com/rustls/rustls)** and **[ring](https://github.com/briansmith/ring)**: the TLS 1.3 stack inside `tls/`.
- **[wasm-bindgen](https://github.com/rustwasm/wasm-bindgen)**, the **[RustCrypto](https://github.com/RustCrypto)** crates, **[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)**, **[libcrux](https://github.com/cryspen/libcrux)** and the other crates listed in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt), with their licenses.

Written by FacePlant101.

"Signal" is a trademark of Signal Messenger, LLC. signal-edge is an independent, unofficial project, not affiliated with or endorsed by Signal Messenger, LLC. See [NOTICE](NOTICE).

## License

AGPL-3.0-only (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). libsignal, which `sealed/` and `@getmaapp/signal-wasm` are built from, is AGPL-3.0. If you run a modified version as a network service, the AGPL requires you to offer its source to that service's users. The prebuilt WebAssembly also contains crates under MIT, Apache-2.0, ISC, BSD, MPL-2.0 and Unicode licenses; their notices are in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).
