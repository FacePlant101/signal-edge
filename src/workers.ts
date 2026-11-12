/**
 * Cloudflare Workers entry point: everything from "signal-edge", with TCP from `cloudflare:sockets`
 * and the WASM modules bundled by Wrangler (as compiled modules) already configured.
 */
import { connect } from "cloudflare:sockets";
import signalWasm from "@getmaapp/signal-wasm/signal_wasm_bg.wasm";
import sealedWasm from "./vendor/signal-sealed/signal_sealed_bg.wasm";
import tlsWasm from "./vendor/signal-tls/signal_tls_bg.wasm";
import opusWasm from "./vendor/signal-opus/signal_opus_bg.wasm";
import { configure } from "./runtime.js";
import type { SignalClientOptions } from "./client.js";
import type { SqlDatabase, SqlValue } from "./sql.js";

configure({
	// Signal's servers use Signal's own CA, which fetch() can't verify: plain TCP, TLS in WASM.
	connect: (hostname, port) => connect({ hostname, port }, { secureTransport: "off", allowHalfOpen: false }),
	wasm: { signal: signalWasm, sealed: sealedWasm, tls: tlsWasm, opus: opusWasm },
});

export * from "./index.js";

/** The subset of DurableObjectStorage the adapters use. */
type DurableObjectStorageLike = {
	sql: { exec(query: string, ...bindings: any[]): { toArray(): unknown[] } };
	transactionSync<T>(fn: () => T): T;
	getAlarm(): Promise<number | null>;
	setAlarm(at: number): Promise<void>;
};

/** Durable Object SQLite as a SqlDatabase. */
export function durableObjectSql(storage: Pick<DurableObjectStorageLike, "sql" | "transactionSync">): SqlDatabase {
	return {
		exec: <T>(query: string, ...bindings: SqlValue[]) => storage.sql.exec(query, ...bindings).toArray() as T[],
		transaction: (fn) => storage.transactionSync(fn),
	};
}

/**
 * SignalClient options for a Durable Object: its SQLite, `waitUntil`, and maintenance through the
 * object's alarm (moved earlier, never later). Forward the alarm yourself:
 * `async alarm() { const next = await this.client.maintain(); if (next) await this.ctx.storage.setAlarm(next); }`
 */
export function durableObjectHost(ctx: { storage: DurableObjectStorageLike; waitUntil(p: Promise<unknown>): void }): Pick<SignalClientOptions, "db" | "waitUntil" | "scheduleMaintenance"> {
	return {
		db: durableObjectSql(ctx.storage),
		waitUntil: (p) => ctx.waitUntil(p),
		scheduleMaintenance: async (at) => {
			const current = await ctx.storage.getAlarm();
			if (current === null || current > at) await ctx.storage.setAlarm(at);
		},
	};
}
