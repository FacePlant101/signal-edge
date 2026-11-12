// Node host for the tests: node:sqlite as the SqlDatabase and WASM read from disk. No sockets: the tests
// make no network calls.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { DatabaseSync } from "node:sqlite";
import { configure } from "../dist/index.js";

const require = createRequire(import.meta.url);
const wasm = (path) => new WebAssembly.Module(readFileSync(path));

configure({
	wasm: {
		signal: wasm(require.resolve("@getmaapp/signal-wasm/signal_wasm_bg.wasm")),
		sealed: wasm(new URL("../dist/vendor/signal-sealed/signal_sealed_bg.wasm", import.meta.url)),
		tls: wasm(new URL("../dist/vendor/signal-tls/signal_tls_bg.wasm", import.meta.url)),
		opus: wasm(new URL("../dist/vendor/signal-opus/signal_opus_bg.wasm", import.meta.url)),
	},
});

let savepoints = 0;

/** A fresh in-memory database. Transactions nest through savepoints, like Durable Object storage. */
export function memoryDb() {
	const db = new DatabaseSync(":memory:");
	return {
		exec(query, ...bindings) {
			const st = db.prepare(query);
			if (st.columns().length) return st.all(...bindings);
			st.run(...bindings);
			return [];
		},
		transaction(fn) {
			const sp = `sp${++savepoints}`;
			db.exec(`SAVEPOINT ${sp}`);
			try {
				const result = fn();
				db.exec(`RELEASE ${sp}`);
				return result;
			} catch (e) {
				db.exec(`ROLLBACK TO ${sp}`);
				db.exec(`RELEASE ${sp}`);
				throw e;
			}
		},
	};
}

export const TEST_STORAGE_KEY = Buffer.alloc(32, 7).toString("base64");
