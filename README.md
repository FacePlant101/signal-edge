# signal-edge

A Signal client that runs as a **linked device** (like Signal Desktop) inside Cloudflare Workers or Node.js, or any JavaScript runtime that can open a TCP socket and run WebAssembly. It links to an existing Signal account with a QR code, or registers a phone number as a new **standalone** account with no phone app (like Signal Desktop's nightly builds). It keeps a live connection to Signal, decrypts what arrives, and sends 1:1 and group messages with attachments, quotes, reactions and mentions. It can also place and answer 1:1 **voice calls** with Signal's apps, speaking RingRTC's protocol over a TURN relay. No signal-cli, JVM, container or VPS.

> **Unofficial.** This is not Signal's software, Signal doesn't support it, and it can break whenever Signal changes its servers. Try it with a spare number first. It handles real end-to-end-encrypted traffic and stores keys that can read it: treat the storage key like a password.

It has run a real account in production on Cloudflare Workers since 2026-11-09.

## What works

| Area | Status |
|---|---|
| Linking (provisioning socket, QR code, `PUT /v1/devices/link`) | verified on a real account |
| Standalone registration (verification session, captcha, SMS/voice code, `POST /v1/registration`; no PIN) | built; not yet run against Signal |
| Signal Login: taking over an account by its Account ID and Account Key (recovery by ACI, `POST /v1/registration`), accounts without a phone number (no PNI, group credentials from the auth credential salt) | built; not yet run against Signal |
| Receive loop (authenticated WebSocket, sealed sender, 1:1, groups via sender keys, sync transcripts, receipts, typing) | verified on a real account |
| Prekeys (one-time, Kyber, signed, last resort; refill and rotation like Desktop) | verified on a real account |
| 1:1 and group text sends, sync transcripts to your other devices | verified on a real account |
| Contacts and groups (storage service, zkgroup credentials, group state) | verified on a real account |
| Attachment download and decryption, long received texts | verified on a real account |
| Safety-number changes (accepted like the apps do, recorded in the chat) | verified on Workers (self-test) |
| Sealed-sender sends | accepted by Signal on a real account |
| Retry requests (resend after a failed decrypt) | self-test only; not yet seen on a real account |
| Sending attachments and long texts (long-text attachment past 2000 bytes) | deployed; not yet seen by a real recipient |
| Sender-key group sends (`multi_recipient`, group send endorsements; falls back to one copy per member) | deployed; not yet run in a group of 3+ |
| Disappearing-message timers, quoted replies, reactions, mentions | built; not yet seen on real clients |
| Counters and last errors that survive restarts | built |
| 1:1 voice calls (RingRTC signaling, ICE over TURN/TCP, SRTP AES-256-GCM, Opus packets; see [Calls](#calls)) | loopback-tested (two of our call stacks through a test TURN server); not yet run against a phone |
| Node.js (`signal-edge/node`) | unit-tested; CI reaches Signal's servers with it on every run (TLS, provisioning socket); not yet run against an account |

Not there yet: phone-number lookup (CDSI needs SGX attestation, so recipients are ACIs), delivery/read receipts, stories, video and group calls, a PIN and registration lock for standalone accounts (SVR2 needs SGX attestation, so such an account can only be registered again with a new code), profile avatars and about text, usernames.

## How it works

```
SignalClient            linking, receive loop, send, contacts/groups, keys, retries, calls
  protocol/             envelopes, Content, sender, receiver, stores, groups, storage service
  calling/              call state machine, RingRTC signaling, ICE, TURN over TCP, SRTP, RTP
    opus/ (C, Rust)     libopus 1.5.2, fixed point, for opusCodec()
    signal-wasm         libsignal sessions, ratchet, prekeys, sender keys  (@getmaapp/signal-wasm)
    sealed/ (Rust)      sealed sender seal/unseal, zkgroup, access keys    (libsignal v0.106.1)
  net/                  HTTP/1.1, WebSocket, TLS socket
    tls/ (Rust)         TLS 1.3 (rustls + ring) trusting only Signal's two roots
  runtime               connect(host, port) → raw TCP; the three WASM modules
  SqlDatabase           synchronous SQLite: Durable Object storage, node:sqlite, …
```

Signal's servers present certificates from Signal's own root CA. `fetch()` on Workers can't verify that (you get HTTP 526), so the library opens a plain TCP socket and runs TLS itself in WebAssembly, pinned to Signal's two root certificates, as libsignal does. WebSockets and HTTP are framed on top of that.

The contents the client stores (account secrets, keys, sessions, message bodies and attachments' keys, contacts' names and profile keys, group state) are encrypted with AES-256-GCM under your storage key, and each row's location is bound into the encryption, so a row copied elsewhere won't decrypt. Metadata used to look rows up is not: account and contact ids (ACIs), conversation ids, authors and timestamps, which groups exist, and error texts. That is who talks to whom and when, so keep the database itself private as well (`nodeSqlite` creates its file with mode 0600). The phone number is only kept sealed.

## Install

```sh
npm install signal-edge
```

Or from GitHub, e.g. to try an unreleased commit (the `prepare` script builds `dist/`): `npm install github:FacePlant101/signal-edge#<commit>`.

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

## Node.js

Node 22.13 or later (CI tests 22, 24 and 26; 26 is the default, see `.nvmrc`). `signal-edge/node` sets up TCP (`node:net`) and the WASM modules, stores everything in a SQLite file, and runs maintenance on a timer:

```js
import { createNodeClient } from "signal-edge/node";

const { client, shutdown } = createNodeClient({
	database: "signal.db", // a path (node:sqlite, WAL mode), or an open node:sqlite / better-sqlite3 database
	storageKey: process.env.SIGNAL_STORAGE_KEY, // 32 random bytes, base64
	deviceName: "My bot",
	onMessages: (records) => console.log(records),
});

const link = await client.startLink(); // { state: "waiting_for_scan", url: "sgnl://linkdevice?…" } → show as QR
// …once client.status().state === "linked": it connects and stays connected by itself
await client.sendText("self", "hello from Node");
process.once("SIGINT", () => shutdown()); // closes the socket and the database
```

[`examples/node`](examples/node) is a small CLI: `link`, `status`, `listen`, `send`. The building blocks are exported too: `nodeConnect` (a TCP connection as web streams) and `nodeSqlite` (a `SqlDatabase` over node:sqlite or better-sqlite3).

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

The WASM files are `@getmaapp/signal-wasm/signal_wasm_bg.wasm`, `signal-edge/wasm/signal-sealed/signal_sealed_bg.wasm` and `signal-edge/wasm/signal-tls/signal_tls_bg.wasm`. `SqlDatabase` is two methods, `exec(query, ...bindings) → rows` and `transaction(fn)`. [`src/node.ts`](src/node.ts) is a complete example of both. Deno's Node compatibility should run `signal-edge/node` as is (untested); Bun would need its own SQLite adapter.

## API

`SignalClient`:

| Method | What |
|---|---|
| `status()`, `self()` | link state; our ACI/PNI/device once linked |
| `startLink()` | opens the provisioning socket, returns the `sgnl://linkdevice` URL; linking finishes in the background (`waitUntil`) |
| `startRegistration(number)`, `submitCaptcha(token)`, `requestCode("sms" \| "voice")`, `verifyCode(code)` | registers a number (E.164) as a new standalone account, this device as its primary: the server asks for a captcha first (solve one at `signalcaptchas.org/registration/generate.html`, pass the `signalcaptcha://…` token), then sends a code. Registering a number that is in use moves its account here and signs out the phone that had it |
| `loginWithAccountKey(accountId, accountKey, { totp? })` | makes this device the primary of an existing account: Signal Login's Account ID (the ACI) and Account Key (the account entropy pool) prove it, as with an account registered without a phone number in Signal's app. The device that had the account is signed out; new identity keys (contacts see a new safety number), the profile key comes back from the storage service |
| `setProfileName(given, family?)`, `profileName()` | the account's profile name, as its primary device (`PUT /v1/profile`, encrypted with the profile key); people we message see it once their app fetches the profile |
| `maintain()` | watchdog: (re)connects the receive socket, prunes retry state, refreshes prekeys and contacts when due; returns when to run next |
| `startReceiving()`, `stopReceiving()`, `receiveStatus()` | the receive socket and its counters |
| `sendText(to, body, files?, extras?)` | `to` = `"self"`, `aci:<uuid>` or `group:<id>`; `files` = forwarded attachments (`{ref}`), text or base64; `extras` = `replyTo` / `reaction` by a stored message's sentAt; `@[aci:<uuid>]` in group text is a mention. Returns devices reached, sealed-sender and sender-key use, sync result, safety-number changes |
| `notifySelf(body)`, `notifyContact(aci, body)` | a message that isn't stored, logged or synced (for one-time codes): to Note to Self, or to a contact, e.g. the owner of a standalone account |
| `messages(limit, chat?)`, `conversations()`, `chats()` | stored history; chats include known groups and contact names |
| `syncDirectory()`, `contacts()`, `groups()`, `group(id, refresh?)`, `names()` | contacts and groups (no keys in the output) |
| `attachment(messageId, index, maxBytes?)` | downloads and decrypts an attachment of a stored message |
| `startCall(to, opts?)`, `calls()`; options `onIncomingCall`, `callOptions` | 1:1 voice calls, see [Calls](#calls); `opusCodec()` for PCM |
| `refreshKeys(force?)`, `keyStatus()`, `whoami()` | prekey maintenance and a credentials check |
| `reset()` | forgets the account locally (empties `SIGNAL_TABLES`) |
| `messageStore()`, `directory()` | lower-level stores |

The building blocks are exported too (`signalFetch`, `SignalSocket`, `ProtocolStore`, `receiveEnvelope`, `sendToServiceId`, `readStorage`, `fetchGroupState`, `unseal`, `decryptAttachment`, …), for anyone who wants to drive the protocol themselves. `signal-edge/selftest` has three self-tests that need no network: link crypto, store persistence, and the receive path (sealed sender, sender keys, identity changes, retry requests).

## Calls

1:1 voice calls with Signal's phone and desktop apps:

```ts
const client = new SignalClient({
	...durableObjectHost(ctx),
	storageKey,
	// Without this, incoming calls are ignored here (your other devices still ring).
	onIncomingCall: (call) => {
		call.onAudio = (p) => call.sendAudio(p.opus); // echo: they hear themselves
		void call.accept(); // or call.decline()
	},
});

const call = await client.startCall("aci:<uuid>"); // rings all their devices
call.onState = (state) => console.log(state); // calling → ringing → connected → ended
call.onAudio = ({ opus }) => {}; // Opus packets from them (48 kHz, mono)
call.sendAudio(opusPacket); // queued and paced at real time; clearAudio() drops what's queued
console.log(await call.ended); // "hangup", "remote-hangup", "declined", "busy", "timeout", "failed", …
```

Audio is Opus packets in and out (any frame size up to 120 ms; Signal's apps send 60 ms). For PCM (48 kHz, mono, `Int16Array`), give calls a codec. `opusCodec()` is libopus 1.5.2 compiled to WebAssembly, set up as RingRTC sets up Opus: VoIP, constant 32 kbit/s, in-band FEC and DTX.

```ts
import { opusCodec } from "signal-edge/workers";

new SignalClient({ ...host, callOptions: { codec: () => opusCodec() } }); // or per call: startCall(to, { codec })
call.sendPcm(samples); // any length; framed into 20 ms (opusCodec({ frameMs: 60 }) for fewer packets)
call.onPcm = (pcm) => {}; // decoded audio; short losses are concealed (with FEC from the next packet)
```

Any object with `encode(Int16Array) → Uint8Array` and `decode(Uint8Array) → Int16Array` will do instead (`OpusCodec`).

How it works (following RingRTC, the calling library inside Signal's apps):

- **Signaling** goes over the normal message path: `CallMessage` offers (urgent, so phones wake up), answers, ICE candidates, hangups and busy, each carrying RingRTC's opaque `ConnectionParametersV4` (an X25519 public key and ICE credentials). Offers older than a minute are ignored, as in RingRTC.
- **Transport**: Workers can't send UDP, so the call allocates a relay on one of Signal's TURN servers (`GET /v2/calling/relays`) and reaches it over **TCP** (`turn:` URLs; `turns:` is skipped because the runtime connector is plain TCP). ICE checks run from that relay to each candidate the other side signals. Private, mDNS and TCP candidates can't be reached from a relay and are skipped or fail. Consent checks keep the path alive, and the call fails if the peer goes quiet for 30 s.
- **Media**: SRTP with AEAD_AES_256_GCM. The keys are HKDF over the X25519 agreement plus both identity keys (so a call is bound to the safety number, as in RingRTC), with no DTLS. Opus goes on payload type 102, and our SSRC is 1002 as the caller or 2002 as the callee. Incoming video and RTCP are dropped unread.
- **Control**: RingRTC's RTP data channel (payload type 101) carries "accepted", hangups and our sender status. When you call someone with several devices, each device that answers gets its own ICE and SRTP leg. The first one to send "accepted" wins, and the others are told "accepted on another device".

On Workers, a call's TURN connection keeps the Durable Object alive for as long as the call lasts. Call signaling arrives on the receive socket, so keep it up (`maintain()` does). Calls are one at a time: a second incoming call is answered busy. Who may call (strangers, message requests) is for your `onIncomingCall` to decide.

Status: the protocol pieces are tested against published vectors (RFC 5769 STUN, RFC 7714 SRTP-GCM, RFC 6188 key derivation), and whole calls are tested between two of our own stacks through a test TURN server (`test/call-loopback.test.mjs`). Interop with RingRTC is built from its source (signaling.proto, rtp_data.proto, `negotiate_srtp_keys`, and the SDP that `Rust_sessionDescriptionFromV4` builds) but hasn't been run against a phone yet. The example Worker has `POST /call` (rings someone and echoes their voice back) and `ANSWER_CALLS=echo`, so this can be checked with two Signal accounts.

## Storage

The client owns these tables (`SIGNAL_TABLES`): `kv`, `failed_envelopes`, `prekeys`, `signed_prekeys`, `kyber_prekeys`, `kyber_usage`, `sessions`, `sender_keys`, `key_counters`, `messages`, `groups`, `contacts`, `send_log`, `seen_envelopes`, `chat_timers`, `sender_key_shares`, `counters`, `last_errors`, `identities`. Your app can keep its own tables in the same database. Don't reuse these names, except to add your own keys to `kv`. Table names, column layouts and encryption labels are stable across versions, so an existing database keeps working after an upgrade.

## Development

```sh
npm install        # also builds dist/
npm run typecheck
npm test           # builds, then runs the unit tests and self-tests in Node (node:sqlite)
SIGNAL_NETWORK_TESTS=1 npm test   # also connects to Signal's servers (no account); CI does this
cd examples/worker && npm install && npm run check   # typecheck + wrangler bundle (dry run)
```

The WASM in `src/vendor/` (`tls/`, `sealed/`, and `opus/`, which compiles libopus fetched by `scripts/build-opus.sh` at a pinned commit) is built by GitHub Actions (`.github/workflows/wasm.yml`), reproducibly: a pinned toolchain (`rust-toolchain.toml`, `wasm-bindgen-cli` 0.2.130, Ubuntu 24.04's clang 18) and no local paths in the output. Every change to the Rust code or the binaries is rebuilt in CI and must match the committed files byte for byte, and each build on `main` gets a provenance attestation (`gh attestation verify src/vendor/signal-tls/signal_tls_bg.wasm -R FacePlant101/signal-edge --signer-workflow FacePlant101/signal-edge/.github/workflows/wasm.yml --source-ref refs/heads/main`). After changing `tls/`, `sealed/` or `opus/`, either run `npm run build:tls` / `npm run build:sealed` / `npm run build:opus` with that toolchain (rustup, clang and llvm-ar, `wasm-bindgen-cli` 0.2.130, `protoc`) and commit `src/vendor/`, or run the WASM workflow on your branch with `commit` ticked. Releases: bump `version` in package.json and add to CHANGELOG.md in a PR; after it merges, push the tag `v<version>`: the Release workflow tests the tagged commit and stages that version on npm (`npm stage publish`, with provenance), and it goes public once a maintainer approves it with 2FA. After a change to either `Cargo.lock`, regenerate the license notices with `python3 scripts/third-party-licenses.py` and commit `THIRD_PARTY_LICENSES.txt`.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md) for how, what is in scope, and what the library assumes.

## Credits

signal-edge stands on Signal's own work. Thanks to:

- **[Signal Messenger](https://signal.org)**: [Signal-Desktop](https://github.com/signalapp/Signal-Desktop), whose linking, sending, receiving, groups and storage-service code this library follows and in places ports (each source file names the Desktop functions it follows), and [libsignal](https://github.com/signalapp/libsignal), whose Rust crates `sealed/` is built on and whose root certificates `tls/` pins. [Signal-Android](https://github.com/signalapp/Signal-Android) was a reference for timer behaviour.
- **[signal-wasm](https://github.com/getmaapp/signal-wasm)** by getmaapp: libsignal compiled to WebAssembly. It made a Worker-native client possible.
- **[rustls](https://github.com/rustls/rustls)** and **[ring](https://github.com/briansmith/ring)**: the TLS 1.3 stack inside `tls/`.
- **[RingRTC](https://github.com/signalapp/ringrtc)** by Signal: the call protocol `src/calling/` speaks. **[libopus](https://opus-codec.org)** by Xiph.Org and contributors (BSD-3-Clause): the codec inside `opus/`.
- **[wasm-bindgen](https://github.com/rustwasm/wasm-bindgen)**, the **[RustCrypto](https://github.com/RustCrypto)** crates, **[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)**, **[libcrux](https://github.com/cryspen/libcrux)** and the other crates listed in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt), with their licenses.

Written by FacePlant101.

"Signal" is a trademark of Signal Messenger, LLC. signal-edge is an independent, unofficial project, not affiliated with or endorsed by Signal Messenger, LLC. See [NOTICE](NOTICE).

## License

AGPL-3.0-only (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). libsignal, which `sealed/` and `@getmaapp/signal-wasm` are built from, is AGPL-3.0. If you run a modified version as a network service, the AGPL requires you to offer its source to that service's users. The prebuilt WebAssembly also contains libopus (BSD-3-Clause) and crates under MIT, Apache-2.0, ISC, BSD, MPL-2.0 and Unicode licenses; their notices are in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).
