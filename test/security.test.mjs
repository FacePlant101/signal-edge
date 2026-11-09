// Regression tests for the security review's findings (each names the finding it covers).
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { memoryDb, TEST_STORAGE_KEY } from "./node-host.mjs";
import { encodeProto, keepGroups, parseContent, Sealer, SignalClient } from "../dist/index.js";
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
	const parsed = parseContent(content, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", bytes(32, 9));
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
