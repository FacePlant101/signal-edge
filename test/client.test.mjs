import assert from "node:assert/strict";
import { test } from "node:test";
import { memoryDb, TEST_STORAGE_KEY } from "./node-host.mjs";
import { SIGNAL_TABLES, SignalClient } from "../dist/index.js";

test("a new client is unlinked and needs no maintenance", async () => {
	const scheduled = [];
	const client = new SignalClient({ db: memoryDb(), storageKey: TEST_STORAGE_KEY, scheduleMaintenance: (at) => scheduled.push(at) });
	assert.deepEqual(client.status(), { state: "unlinked" });
	assert.equal(client.self(), undefined);
	assert.equal(await client.maintain(), undefined);
	assert.deepEqual(scheduled, []);
	assert.equal(client.receiveStatus().messages, 0);
});

test("constructor creates every table it owns", () => {
	const db = memoryDb();
	new SignalClient({ db, storageKey: TEST_STORAGE_KEY });
	const tables = new Set(db.exec("SELECT name FROM sqlite_master WHERE type = 'table'").map((r) => r.name));
	for (const t of SIGNAL_TABLES) assert.ok(tables.has(t), `missing table ${t}`);
});

test("a linked client asks for maintenance on start, and reset forgets it", async () => {
	const db = memoryDb();
	const link = { state: "linked", aci: "11111111-1111-4111-8111-111111111111", deviceId: 3, linkedAt: 1 };
	db.exec("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)");
	db.exec("INSERT INTO kv (key, value) VALUES ('account_meta', ?)", new TextEncoder().encode(JSON.stringify(link)));
	const scheduled = [];
	const client = new SignalClient({ db, storageKey: TEST_STORAGE_KEY, scheduleMaintenance: (at) => scheduled.push(at) });
	assert.equal(client.status().state, "linked");
	assert.deepEqual(client.self(), { aci: link.aci, pni: undefined, deviceId: 3 });
	assert.equal(scheduled.length, 1);
	await client.reset();
	assert.equal(client.status().state, "unlinked");
	assert.equal(db.exec("SELECT COUNT(*) AS n FROM kv")[0].n, 0);
	// A restarted client reads the cleared state.
	assert.equal(new SignalClient({ db, storageKey: TEST_STORAGE_KEY }).status().state, "unlinked");
});

test("linking refuses a missing or short storage key before touching the network", async () => {
	for (const storageKey of [undefined, Buffer.alloc(16).toString("base64")]) {
		const client = new SignalClient({ db: memoryDb(), storageKey });
		await assert.rejects(client.startLink(), /storage key must be 32 bytes/);
	}
});

test("sending needs a linked account and checks input first", async () => {
	const client = new SignalClient({ db: memoryDb(), storageKey: TEST_STORAGE_KEY });
	await assert.rejects(client.sendText("self", "  "), /empty message/);
	await assert.rejects(client.sendText("self", "x".repeat(2001)), /longer than 2000 bytes/);
	await assert.rejects(client.sendText("self", "hi"), /not linked/);
});
