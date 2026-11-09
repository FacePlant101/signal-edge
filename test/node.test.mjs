// The Node entry point: TCP adapter, SQLite adapter, the timer host, and that importing
// "signal-edge/node" alone is enough to run the library.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import net from "node:net";
import { test } from "node:test";
import { promisify } from "node:util";
import { createNodeClient, nodeConnect, nodeSqlite } from "signal-edge/node";

const KEY = Buffer.alloc(32, 9).toString("base64");

test("nodeConnect: bytes go out and come back over plain TCP", async () => {
	const server = net.createServer((s) => s.pipe(s)); // echo
	await new Promise((r) => server.listen(0, "127.0.0.1", r));
	try {
		const sock = nodeConnect("127.0.0.1", server.address().port);
		await sock.opened;
		const writer = sock.writable.getWriter();
		const reader = sock.readable.getReader();
		await writer.write(new TextEncoder().encode("ping"));
		let got = "";
		while (got.length < 4) got += new TextDecoder().decode((await reader.read()).value);
		assert.equal(got, "ping");
		reader.releaseLock();
		writer.releaseLock();
		await sock.close();
	} finally {
		server.close();
	}
});

test("nodeConnect: a refused connection rejects opened", async () => {
	const server = net.createServer();
	await new Promise((r) => server.listen(0, "127.0.0.1", r));
	const port = server.address().port;
	await new Promise((r) => server.close(r));
	await assert.rejects(nodeConnect("127.0.0.1", port).opened, /ECONNREFUSED/);
});

test("nodeSqlite: rows, BLOBs, RETURNING and nested transactions", () => {
	const db = nodeSqlite(":memory:");
	db.exec("CREATE TABLE t (k TEXT PRIMARY KEY, v BLOB)");
	const bytes = new Uint8Array([1, 2, 3, 250]);
	// node:sqlite rows have no prototype; compare their contents.
	assert.deepEqual(db.exec("INSERT INTO t VALUES (?, ?) RETURNING k", "a", bytes).map((r) => ({ ...r })), [{ k: "a" }]);
	const [row] = db.exec("SELECT v FROM t WHERE k = ?", "a");
	assert.deepEqual([...row.v], [...bytes]);
	db.transaction(() => {
		db.exec("INSERT INTO t VALUES ('b', NULL)");
		assert.throws(() =>
			db.transaction(() => {
				db.exec("INSERT INTO t VALUES ('c', NULL)");
				throw new Error("inner");
			}),
		);
	});
	assert.deepEqual(db.exec("SELECT k FROM t ORDER BY k").map((r) => r.k), ["a", "b"]);
	assert.throws(() =>
		db.transaction(() => {
			db.exec("INSERT INTO t VALUES ('d', NULL)");
			throw new Error("outer");
		}),
	);
	assert.equal(db.exec("SELECT COUNT(*) AS n FROM t")[0].n, 2);
	db.close();
});

test("createNodeClient: unlinked, no maintenance, clean shutdown", async () => {
	const { client, shutdown } = createNodeClient({ database: ":memory:", storageKey: KEY });
	assert.equal(client.status().state, "unlinked");
	assert.equal(await client.maintain(), undefined);
	await shutdown();
});

test("createNodeClient: a linked client runs maintenance on its timer", async () => {
	const db = nodeSqlite(":memory:");
	db.exec("CREATE TABLE kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)");
	const link = { state: "linked", aci: "11111111-1111-4111-8111-111111111111", deviceId: 3, linkedAt: 1 };
	db.exec("INSERT INTO kv VALUES ('account_meta', ?)", new TextEncoder().encode(JSON.stringify(link)));
	const quiet = console.error;
	console.error = () => {}; // maintenance fails without account secrets; that is expected here
	try {
		const { client, shutdown } = createNodeClient({ database: db, storageKey: KEY });
		assert.equal(client.status().state, "linked");
		// The constructor asks for maintenance in 1 s; a failed key refresh records its retry time in kv.
		const deadline = Date.now() + 5000;
		while (!db.exec("SELECT 1 FROM kv WHERE key = 'next_key_refresh'").length && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
		assert.ok(db.exec("SELECT 1 FROM kv WHERE key = 'next_key_refresh'").length, "maintain() did not run");
		await shutdown();
	} finally {
		console.error = quiet;
		db.close();
	}
});

test('importing "signal-edge/node" alone runs the library (fresh process)', async () => {
	const script = `
		const { nodeSqlite, Sealer } = await import("signal-edge/node");
		const { receiverSelfTest } = await import("signal-edge/selftest");
		const r = await receiverSelfTest(nodeSqlite(":memory:"), await Sealer.fromBase64("${KEY}"));
		console.log(JSON.stringify({ ok: r.ok }));`;
	const { stdout } = await promisify(execFile)(process.execPath, ["--no-warnings", "--input-type=module", "-e", script], { cwd: new URL("..", import.meta.url) });
	assert.deepEqual(JSON.parse(stdout.trim().split("\n").pop()), { ok: true });
});
