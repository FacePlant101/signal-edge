/**
 * Node.js entry point (22.13 or later): everything from "signal-edge", with TCP from `node:net` and the
 * WASM modules read from this package, already configured; plus SQLite storage (`nodeSqlite`) and a
 * host that runs maintenance on a timer (`createNodeClient`).
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import net from "node:net";
import { Duplex } from "node:stream";
// Through the package's own name, so this file (built in a second pass with Node's types) is checked
// against the core's declarations instead of re-checking the core, which is typed for Workers.
import { configure, SignalClient, type RawSocket, type SignalClientOptions, type SqlDatabase, type SqlValue } from "signal-edge";

const require = createRequire(import.meta.url);

/** Compiled once, when this module is first imported. */
const [signalWasm, sealedWasm, tlsWasm] = await Promise.all([
	readFile(require.resolve("@getmaapp/signal-wasm/signal_wasm_bg.wasm")),
	readFile(new URL("./vendor/signal-sealed/signal_sealed_bg.wasm", import.meta.url)),
	readFile(new URL("./vendor/signal-tls/signal_tls_bg.wasm", import.meta.url)),
].map(async (bytes) => WebAssembly.compile(await bytes)));

configure({
	// Signal's servers use Signal's own CA: plain TCP here, TLS in WASM pinned to Signal's roots.
	connect: nodeConnect,
	wasm: { signal: signalWasm!, sealed: sealedWasm!, tls: tlsWasm! },
});

export * from "signal-edge";

/** A plain TCP connection as the web streams the library reads and writes. */
export function nodeConnect(hostname: string, port: number): RawSocket {
	const socket = net.connect({ host: hostname, port, noDelay: true, keepAlive: true, keepAliveInitialDelay: 30_000 });
	const opened = new Promise<void>((resolve, reject) => {
		socket.once("connect", () => {
			socket.off("error", reject);
			resolve();
		});
		socket.once("error", reject);
	});
	// Duplex.toWeb listens for errors itself and surfaces them on the streams.
	const { readable, writable } = Duplex.toWeb(socket) as unknown as Pick<RawSocket, "readable" | "writable">;
	return {
		readable,
		writable,
		opened,
		close: async () => {
			socket.destroy();
		},
	};
}

/** The parts of node:sqlite's DatabaseSync and better-sqlite3's Database that nodeSqlite uses. */
export type SqliteDatabaseLike = {
	prepare(sql: string): {
		all(...params: unknown[]): unknown[];
		run(...params: unknown[]): unknown;
		/** better-sqlite3: whether the statement returns rows. */
		reader?: boolean;
		/** node:sqlite: the result columns (empty for statements without rows). */
		columns?(): unknown[];
	};
	exec(sql: string): unknown;
	close?(): unknown;
};

/**
 * SQLite as a SqlDatabase. Pass a file path (opened with node:sqlite, in WAL mode) or an open
 * node:sqlite or better-sqlite3 database. Transactions nest through savepoints.
 */
export function nodeSqlite(database: string | SqliteDatabaseLike): SqlDatabase & { close(): void } {
	let db: SqliteDatabaseLike;
	let owned = false;
	if (typeof database === "string") {
		const { DatabaseSync } = require("node:sqlite") as { DatabaseSync: new (path: string) => SqliteDatabaseLike };
		db = new DatabaseSync(database);
		owned = true;
		db.exec("PRAGMA journal_mode = WAL");
		db.exec("PRAGMA busy_timeout = 5000");
	} else {
		db = database;
	}
	let depth = 0;
	return {
		exec<T>(query: string, ...bindings: SqlValue[]): T[] {
			const st = db.prepare(query);
			const params = bindings.map(toSqlite);
			const returnsRows = typeof st.reader === "boolean" ? st.reader : (st.columns?.().length ?? 0) > 0;
			if (returnsRows) return st.all(...params) as T[];
			st.run(...params);
			return [];
		},
		transaction<T>(fn: () => T): T {
			const sp = `signal_edge_${++depth}`;
			db.exec(`SAVEPOINT ${sp}`);
			try {
				const result = fn();
				db.exec(`RELEASE ${sp}`);
				return result;
			} catch (e) {
				db.exec(`ROLLBACK TO ${sp}`);
				db.exec(`RELEASE ${sp}`);
				throw e;
			} finally {
				depth--;
			}
		},
		close() {
			if (owned) db.close?.();
		},
	};
}

/** Both drivers take Buffers for BLOBs; node:sqlite also takes Uint8Array, better-sqlite3 needs a Buffer. */
function toSqlite(v: SqlValue): unknown {
	if (v instanceof Uint8Array) return Buffer.isBuffer(v) ? v : Buffer.from(v.buffer, v.byteOffset, v.byteLength);
	if (v instanceof ArrayBuffer) return Buffer.from(v);
	return v;
}

export type NodeClientOptions = Omit<SignalClientOptions, "db" | "waitUntil" | "scheduleMaintenance"> & {
	/** A SQLite file path, an open node:sqlite or better-sqlite3 database, or any SqlDatabase. */
	database: string | SqliteDatabaseLike | SqlDatabase;
};

export type NodeClient = {
	client: SignalClient;
	/** Stops maintenance, closes the receive socket, waits for background work, and closes the database if it was given as a path. */
	shutdown(): Promise<void>;
};

/**
 * A SignalClient for a long-running Node process. Maintenance (reconnecting, prekeys, contact sync)
 * runs on a timer instead of a Durable Object alarm; call shutdown() before exiting.
 */
export function createNodeClient(opts: NodeClientOptions): NodeClient {
	const { database, ...rest } = opts;
	const isSqlDatabase = typeof database === "object" && "transaction" in database;
	const db: SqlDatabase = isSqlDatabase ? database : nodeSqlite(database as string | SqliteDatabaseLike);
	// Only a database opened here from a path is closed on shutdown; one passed in belongs to the caller.
	const close = typeof database === "string" ? () => (db as ReturnType<typeof nodeSqlite>).close() : () => {};
	const pending = new Set<Promise<unknown>>();
	let timer: ReturnType<typeof setTimeout> | undefined;
	let due: number | undefined;
	let stopped = false;
	let running: Promise<void> | undefined;

	const schedule = (at: number) => {
		if (stopped || running) {
			// A maintain() in progress reschedules itself from its result; keep the earliest ask.
			if (!stopped) due = Math.min(due ?? at, at);
			return;
		}
		if (due !== undefined && due <= at) return;
		due = at;
		clearTimeout(timer);
		timer = setTimeout(run, Math.max(0, at - Date.now()));
	};
	const run = () => {
		timer = undefined;
		due = undefined;
		running = (async () => {
			let next: number | undefined;
			try {
				next = await client.maintain();
			} catch (e) {
				console.error("signal-edge maintenance failed", e);
				next = Date.now() + 60_000;
			}
			running = undefined;
			const asked = due;
			due = undefined;
			const at = Math.min(next ?? Infinity, asked ?? Infinity);
			if (Number.isFinite(at)) schedule(at);
		})();
	};

	const client = new SignalClient({
		...rest,
		db,
		waitUntil: (p) => {
			pending.add(p);
			void p.catch(() => {}).finally(() => pending.delete(p));
		},
		scheduleMaintenance: schedule,
	});

	return {
		client,
		async shutdown() {
			stopped = true;
			clearTimeout(timer);
			timer = undefined;
			await running; // a maintain() in progress may be opening the socket
			await client.stopReceiving();
			await Promise.allSettled([...pending]);
			close();
		},
	};
}
