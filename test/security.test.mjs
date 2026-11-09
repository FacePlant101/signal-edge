// Regression tests for the security review's findings (each names the finding it covers).
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { memoryDb, TEST_STORAGE_KEY } from "./node-host.mjs";
import { AccountForgotten, encodeProto, keepGroups, parseContent, Sealer, SignalClient } from "../dist/index.js";
import { readBody } from "../dist/net/http.js";
import { withDeadline } from "../dist/util/deadline.js";
import { ByteQueue } from "../dist/util/bytes.js";
import { encryptAttachment, maxEncryptedSize, redirectTarget } from "../dist/protocol/attachments.js";
import { preKeyMessageIdentity } from "../dist/protocol/identities.js";
import { groupIdFromMasterKey } from "../dist/protocol/groups.js";
import { receiverSelfTest, storeSelfTest } from "../dist/selftest/index.js";
import { nodeSqlite } from "signal-edge/node";

/** A stream of the given chunks; `poison` makes any read past them fail the test. */
function stream(chunks, poison = false) {
	let i = 0;
	return new ReadableStream({
		pull(c) {
			if (i < chunks.length) c.enqueue(chunks[i++]);
			else if (poison) c.error(new Error("read past the declared head: the body was read"));
			else c.close();
		},
	});
}
const bytes = (n, v = 1) => new Uint8Array(n).fill(v);

// --- Unbounded downloads ---

test("readBody refuses a Content-Length over the cap without reading the body", async () => {
	const q = new ByteQueue(stream([], true));
	await assert.rejects(readBody(q, new Headers({ "content-length": "100000000" }), 1000), /larger than 1000/);
});

test("readBody stops a chunked body as soon as it passes the cap", async () => {
	const enc = new TextEncoder();
	const q = new ByteQueue(stream([enc.encode("400\r\n"), bytes(1024), enc.encode("\r\n400\r\n")], true));
	await assert.rejects(readBody(q, new Headers({ "transfer-encoding": "chunked" }), 1500), /larger than 1500/);
});

test("readBody stops a body without a length once it passes the cap", async () => {
	const q = new ByteQueue(stream([bytes(800), bytes(800), bytes(800)]));
	await assert.rejects(readBody(q, new Headers(), 1000), /larger than 1000/);
	const ok = new ByteQueue(stream([bytes(400), bytes(400)]));
	assert.equal((await readBody(ok, new Headers(), 1000)).length, 800);
});

test("ByteQueue joins chunks correctly when taking across them", async () => {
	const q = new ByteQueue(stream([new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5, 6])]));
	assert.deepEqual([...(await q.take(4))], [1, 2, 3, 4]);
	assert.deepEqual([...(await q.take(2))], [5, 6]);
});

test("the download cap never refuses a real attachment of the allowed size", async () => {
	for (const size of [0, 1, 540, 541, 4096, 100_000, 2_000_000]) {
		const { blob } = await encryptAttachment(bytes(size));
		assert.ok(blob.length <= maxEncryptedSize(size), `${size}: blob ${blob.length} > cap ${maxEncryptedSize(size)}`);
	}
});

test("a timeout stops the work and closes it", async () => {
	let stopped;
	const never = () => new Promise(() => {});
	await assert.rejects(withDeadline(never, 50, undefined, "slow thing", (e) => (stopped = e)), /timed out after 50 ms/);
	assert.match(String(stopped), /timed out/);
	const ac = new AbortController();
	const p = withDeadline(never, 10_000, ac.signal, "aborted thing", () => {});
	ac.abort(new Error("cancelled by caller"));
	await assert.rejects(p, /cancelled by caller/);
});

test("CDN redirects go only to public https hosts", () => {
	const from = new URL("https://cdn3.signal.org/attachments/x");
	assert.equal(redirectTarget(from, "https://storage.googleapis.com/b/x").hostname, "storage.googleapis.com");
	for (const bad of ["http://example.com/x", "https://127.0.0.1/x", "https://10.1.2.3/", "https://192.168.0.1/", "https://169.254.169.254/latest", "https://[::1]/", "https://localhost/", "file:///etc/passwd"]) {
		assert.throws(() => redirectTarget(from, bad), /refusing a redirect/, bad);
	}
});

// --- Identity keys ---

test("a padded identity key in a PreKey message is checked on its first 33 bytes", () => {
	const key = new Uint8Array([5, ...bytes(32, 7)]);
	const withJunk = new Uint8Array([...key, 0xff]);
	const msg = (k) => new Uint8Array([0x33, ...encodeProto([[3, k]])]);
	assert.deepEqual([...preKeyMessageIdentity(msg(key))], [...key]);
	assert.deepEqual([...preKeyMessageIdentity(msg(withJunk))], [...key], "padded key must not skip the check");
	assert.equal(preKeyMessageIdentity(msg(bytes(20))), undefined);
});

// --- Group messages ---

test("the sealed-sender group id doesn't put a message into a group", () => {
	const data = encodeProto([[1, "hello"], [7, 1700000000000]]); // DataMessage body + timestamp, no group context
	const content = encodeProto([[1, data]]);
	const parsed = parseContent(content, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
	assert.equal(parsed.records[0]?.conversation, "aci:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
});

test("keepGroups drops records, timers and contexts of groups the sender isn't in", () => {
	const allowedKey = bytes(32, 1);
	const otherKey = bytes(32, 2);
	const id = (k) => groupIdFromMasterKey(k); // base64, as conversations name groups
	const parsed = {
		records: [{ conversation: `group:${id(allowedKey)}` }, { conversation: `group:${id(otherKey)}` }, { conversation: "aci:x" }],
		timers: [{ conversation: `group:${id(otherKey)}`, expireTimer: 60 }],
		groups: [{ masterKey: allowedKey, revision: 1 }, { masterKey: otherKey, revision: 9 }],
		kinds: [],
	};
	keepGroups(parsed, new Set([id(allowedKey)]));
	assert.deepEqual(parsed.records.map((r) => r.conversation), [`group:${id(allowedKey)}`, "aci:x"]);
	assert.deepEqual(parsed.timers, []);
	assert.equal(parsed.groups.length, 1);
	// Parsing and the directory derive the same id from a master key.
	const msg = encodeProto([[1, encodeProto([[1, "hi"], [7, 1], [15, encodeProto([[1, allowedKey], [2, 1]])]])]]);
	assert.equal(parseContent(msg, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").records[0]?.conversation, `group:${id(allowedKey)}`);
});

// --- Storage ---

test("the link record kept outside the sealed secrets holds no phone number", () => {
	const db = memoryDb();
	db.exec("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)");
	const link = { state: "linked", aci: "11111111-1111-4111-8111-111111111111", number: "+15550100", deviceId: 3, linkedAt: 1 };
	db.exec("INSERT INTO kv (key, value) VALUES ('account_meta', ?)", new TextEncoder().encode(JSON.stringify(link)));
	new SignalClient({ db, storageKey: TEST_STORAGE_KEY });
	const stored = new TextDecoder().decode(db.exec("SELECT value FROM kv WHERE key = 'account_meta'")[0].value);
	assert.ok(!stored.includes("+15550100"), stored);
	assert.equal(JSON.parse(stored).aci, link.aci);
});

test("after a restart the phone number comes back from the sealed secrets", async () => {
	const db = memoryDb();
	db.exec("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)");
	const aci = "11111111-1111-4111-8111-111111111111";
	const link = { state: "linked", aci, deviceId: 3, linkedAt: 1 };
	db.exec("INSERT INTO kv (key, value) VALUES ('account_meta', ?)", new TextEncoder().encode(JSON.stringify(link)));
	const sealer = await Sealer.fromBase64(TEST_STORAGE_KEY);
	const secrets = await sealer.seal("account_secrets", new TextEncoder().encode(JSON.stringify({ aci, number: "+15550100", deviceId: 3 })));
	db.exec("INSERT INTO kv (key, value) VALUES ('account_secrets', ?)", secrets);
	const client = new SignalClient({ db, storageKey: TEST_STORAGE_KEY });
	for (let i = 0; i < 100 && client.status().number === undefined; i++) await new Promise((r) => setTimeout(r, 5));
	assert.equal(client.status().number, "+15550100");
});

test("work holding the database from before a reset can't touch the next account's data", async () => {
	const db = memoryDb();
	const client = new SignalClient({ db, storageKey: TEST_STORAGE_KEY });
	const before = await client.messageStore();
	const dirBefore = await client.directory();
	await client.reset();
	await assert.rejects(async () => before.conversations(), AccountForgotten);
	await assert.rejects(async () => dirBefore.putGroup({ id: "g", masterKey: "AAAA", source: "message" }), AccountForgotten);
	// What is taken after the reset works.
	assert.deepEqual(await (await client.messageStore()).conversations(), []);
});

test("nodeSqlite creates its database file readable by the owner only", () => {
	const dir = mkdtempSync(join(tmpdir(), "signal-edge-"));
	try {
		const db = nodeSqlite(join(dir, "account.db"));
		db.exec("CREATE TABLE t (x)");
		db.close();
		assert.equal(statSync(join(dir, "account.db")).mode & 0o777, 0o600);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("the self-tests refuse a database that holds an account", async () => {
	const db = memoryDb();
	db.exec("CREATE TABLE kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)");
	db.exec("INSERT INTO kv VALUES ('account_secrets', x'00')");
	const sealer = await Sealer.fromBase64(TEST_STORAGE_KEY);
	await assert.rejects(storeSelfTest(db, sealer), /refusing/);
	await assert.rejects(receiverSelfTest(db, sealer), /refusing/);
});

// --- Review follow-ups ---

test("other people's sender keys are capped in the database and in memory; ours aren't", async () => {
	const { ProtocolStore, createStoreSchema } = await import("../dist/protocol/store.js");
	const { signal } = await import("../dist/protocol/wasm.js");
	const sig = signal();
	const db = memoryDb();
	createStoreSchema(db);
	const sealer = await Sealer.fromBase64(TEST_STORAGE_KEY);
	const priv = sig.WasmPrivateKey.generate();
	const pair = new sig.WasmIdentityKeyPair(priv.getPublicKey(), sig.WasmPrivateKey.deserialize(priv.serialize())).serialize();
	const store = await ProtocolStore.load(db, sealer, "aci", pair, 1);
	const them = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
	const us = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
	const addr = (n, d) => new sig.WasmProtocolAddress(n, d);
	const theirStore = new sig.WasmInMemSenderKeyStore();
	const theirs = [];
	for (let i = 0; i < 260; i++) {
		const id = crypto.randomUUID();
		theirs.push(id);
		const skdm = await sig.createSenderKeyDistribution(addr(them, 1), id, theirStore);
		await sig.processSenderKeyDistribution(addr(them, 1), skdm, store.senderKeys);
		await store.saveSenderKey(them, 1, id);
	}
	const rows = (a) => db.exec("SELECT COUNT(*) AS n FROM sender_keys WHERE address = ?", a)[0].n;
	assert.equal(rows(`${them}.1`), 256);
	assert.equal(await store.senderKeys.export_sender_key(addr(them, 1), theirs[0]), undefined, "the least recently used key left memory too");
	assert.ok(await store.senderKeys.export_sender_key(addr(them, 1), theirs[259]));
	for (let i = 0; i < 260; i++) {
		const id = crypto.randomUUID();
		await sig.createSenderKeyDistribution(addr(us, 3), id, store.senderKeys);
		await store.saveSenderKey(us, 3, id, true);
	}
	assert.equal(rows(`${us}.3`), 260);
});

test("a quoted message is looked up by its author too, not just its timestamp", async () => {
	const { MessageStore, createMessageSchema } = await import("../dist/protocol/messages.js");
	const db = memoryDb();
	createMessageSchema(db);
	const messages = new MessageStore(db, await Sealer.fromBase64(TEST_STORAGE_KEY));
	const conversation = "group:AAAA";
	const record = (author, body) => ({ kind: "message", conversation, author, authorDevice: 1, outgoing: false, sentAt: 1_700_000_000_000, body });
	await messages.add([record("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "real")], "g1", 1);
	await messages.add([record("dddddddd-dddd-4ddd-8ddd-dddddddddddd", "same timestamp")], "g2", 2);
	assert.equal((await messages.findSent(conversation, 1_700_000_000_000, "cccccccc-cccc-4ccc-8ccc-cccccccccccc"))?.body, "real");
	assert.equal(await messages.findSent(conversation, 1_700_000_000_000, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), undefined);
});

test("a refused rate limit names the limit that refused and uses up none of them", async () => {
	const { Limiter } = await import("../dist/protocol/retry.js");
	const l = new Limiter();
	const limits = [
		{ key: "own", max: 2, windowMs: 60_000 },
		{ key: "all", max: 3, windowMs: 60_000 },
	];
	assert.equal(l.refusal(limits, 0), undefined);
	assert.equal(l.refusal(limits, 1), undefined);
	assert.equal(l.refusal(limits, 2), "own");
	assert.equal(l.refusal([{ key: "other", max: 2, windowMs: 60_000 }, limits[1]], 3), undefined); // "all" had room: 2 used
	assert.equal(l.refusal([{ key: "other", max: 2, windowMs: 60_000 }, limits[1]], 4), "all");
	assert.equal(l.allow(limits, 60_001), true); // the window moved on
});

// --- Standalone registration (no network) ---

test("account entropy pools are 64 characters from [0-9a-z]", async () => {
	const { generateAccountEntropyPool } = await import("../dist/index.js");
	const seen = new Set();
	for (let i = 0; i < 50; i++) {
		const aep = generateAccountEntropyPool();
		assert.match(aep, /^[0-9a-z]{64}$/);
		for (const c of aep) seen.add(c);
	}
	assert.equal(seen.size, 36, "every character turns up");
});

test("the registration recovery password matches libsignal's known answer", async () => {
	const { registrationRecoveryPassword } = await import("../dist/index.js");
	const out = await registrationRecoveryPassword(new Uint8Array(32).fill(0x2a));
	assert.equal(Buffer.from(out).toString("hex"), "91f959cfee39676dedd028bc8bbbd1e91ffa6a42c57754d095fe8abe7f0d4f56");
});

test("registration checks its input and its order before any network call", async () => {
	const client = new SignalClient({ db: memoryDb(), storageKey: TEST_STORAGE_KEY });
	await assert.rejects(client.startRegistration("12345678"), /E\.164/);
	await assert.rejects(client.submitCaptcha("signalcaptcha://x"), /no registration in progress/);
	await assert.rejects(client.requestCode("sms"), /no registration in progress/);
	await assert.rejects(client.verifyCode("123456"), /no registration in progress/);
	assert.equal(client.status().state, "unlinked");
});

test("the registration body has the shape libsignal sends", async () => {
	const { registrationBody } = await import("../dist/index.js");
	const key = (id) => ({ keyId: id, publicKey: "cHVi", signature: "c2ln" });
	const body = registrationBody({
		number: "+18005550101",
		sessionId: "abc",
		password: "pw",
		registrationId: 123,
		pniRegistrationId: 456,
		aciIdentityKey: "YWNp",
		pniIdentityKey: "cG5p",
		aciSignedPreKey: key(1),
		pniSignedPreKey: key(2),
		aciPqLastResortPreKey: key(3),
		pniPqLastResortPreKey: key(4),
		unidentifiedAccessKey: new Uint8Array([117, 110, 105, 100]),
		recoveryPassword: new TextEncoder().encode("recovery"),
		capabilities: { spqr: true },
		discoverableByPhoneNumber: false,
	});
	// From libsignal rust/net/chat/src/ws/registration/request.rs register_account_request (fetching messages, no push token).
	assert.deepEqual(body, {
		sessionId: "abc",
		accountAttributes: {
			fetchesMessages: true,
			registrationId: 123,
			pniRegistrationId: 456,
			capabilities: { spqr: true },
			unidentifiedAccessKey: [117, 110, 105, 100],
			unrestrictedUnidentifiedAccess: false,
			discoverableByPhoneNumber: false,
			recoveryPassword: "cmVjb3Zlcnk=",
			registrationLock: null,
		},
		skipDeviceTransfer: true,
		aciIdentityKey: "YWNp",
		pniIdentityKey: "cG5p",
		aciSignedPreKey: key(1),
		pniSignedPreKey: key(2),
		aciPqLastResortPreKey: key(3),
		pniPqLastResortPreKey: key(4),
	});
	assert.equal("pushToken" in body, false);
});

test("registration calls reject (not throw) on bad input", async () => {
	const { createVerificationSession, submitVerificationCode, submitCaptcha } = await import("../dist/index.js");
	for (const call of [() => createVerificationSession("123"), () => submitVerificationCode("s", "abc"), () => submitCaptcha("s", " ")]) {
		let p;
		assert.doesNotThrow(() => (p = call()));
		await assert.rejects(p);
	}
});
