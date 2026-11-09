# Security

signal-edge holds a Signal account's keys and messages, so security problems in it matter. Thank you for reporting them privately.

## Reporting a vulnerability

Please **don't open a public issue**. Report it through GitHub's private vulnerability reporting: the repository's **Security** tab, then **Report a vulnerability** ([direct link](https://github.com/FacePlant101/signal-edge/security/advisories/new)). Only the maintainers see the report.

Please include:
- what an attacker can do, and from where (another Signal user, someone on the network path, Signal's servers, someone with access to the database or the host)
- the version or commit, and the runtime (Workers, Node, other)
- steps or a test that shows it, if you have one. Please use a throwaway Signal account, never someone else's.

Expect an acknowledgement within a week. Fixes are released as a new version, with an advisory that credits you unless you'd rather not be named.

## Supported versions

Only the latest release gets security fixes. The library is pre-1.0, so a fix may come with breaking changes, which the changelog will describe.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | yes       |
| < 0.2   | no        |

## Scope

In scope: everything in this repository. That includes:
- the client (`src/`)
- the TLS crate pinned to Signal's roots (`tls/`)
- the sealed-sender/zkgroup crate (`sealed/`)
- the prebuilt WASM in `src/vendor/`
- the Workers and Node adapters
- the CI workflows that build and publish them

For example:
- anything a message, attachment or group state from another Signal user can make the client do: crash it, exhaust its memory or time, store something it shouldn't, or put words in someone else's mouth
- anything that weakens the pinned TLS or lets a network attacker read or change traffic
- leaks of keys, message contents or the phone number outside the sealed storage
- data from a forgotten account (`reset()`) surviving or mixing with the next one
- ways to get a tampered build into `src/vendor/` or onto npm

Report these elsewhere:
- **libsignal** (Signal's protocol library, compiled into `sealed/` and used through `@getmaapp/signal-wasm`): to Signal, at security@signal.org. If the bug reaches signal-edge users, tell us too.
- **`@getmaapp/signal-wasm`**: to its maintainers.
- **Your own application** built on signal-edge: its authentication, who may call `send`, and what it does with incoming text (for example, handing it to a language model). That is the app's to secure. The README and the notes below describe what the library expects.

## What the library assumes

- **Everything in a message is the sender's word.** That covers sizes, quoted text, group context, mentions and timestamps. The client checks them: downloads are capped by the bytes actually read, group messages from non-members are dropped, and quotes are matched against stored messages. Treat message text as untrusted input in your app too.
- **The storage key** (`storageKey`) encrypts what the client stores (AES-256-GCM, bound to each row's place). Keep it as secret as the account itself. Anyone with the key and the database can act as the linked device.
- **Some metadata is stored unencrypted**: account and contact ids, conversation ids, authors, timestamps, which groups exist, and error texts. This shows who talks to whom and when, so keep the database private as well (see the README, "How it works").
- **Signal's servers** are trusted for availability and for routing. They are not trusted for message contents: those are end-to-end encrypted, and sealed sender hides the sender from the server where the recipient allows it.

## Verifying a build

The WASM in `src/vendor/` is built reproducibly by GitHub Actions and attested on `main`. To check a file:

```sh
gh attestation verify src/vendor/signal-tls/signal_tls_bg.wasm -R FacePlant101/signal-edge \
  --signer-workflow FacePlant101/signal-edge/.github/workflows/wasm.yml --source-ref refs/heads/main
```

npm releases are published from tagged commits on `main` by `.github/workflows/release.yml`. The tarball that workflow tests is the one it publishes.
