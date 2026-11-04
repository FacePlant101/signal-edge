/**
 * What the library needs from its host: a raw TCP connection (TLS runs in WASM on top of it, pinned to
 * Signal's root CAs) and the three WebAssembly modules. `signal-edge/workers` sets both for Cloudflare
 * Workers; other runtimes call `configure()` before using anything else.
 */

/** A plain TCP connection, as `cloudflare:sockets` `connect()` returns one. */
export type RawSocket = {
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	/** Resolves once the connection is up. */
	opened: Promise<unknown>;
	close(): Promise<void>;
};

export type Connect = (hostname: string, port: number) => RawSocket | Promise<RawSocket>;

/** Compiled modules, or their bytes. */
export type WasmSource = WebAssembly.Module | BufferSource;

export type WasmModules = {
	/** `@getmaapp/signal-wasm/signal_wasm_bg.wasm`: sessions, ratchet, prekeys, sender keys. */
	signal: WasmSource;
	/** `signal-edge/wasm/signal-sealed/signal_sealed_bg.wasm`: sealed sender and zkgroup (sealed/). */
	sealed: WasmSource;
	/** `signal-edge/wasm/signal-tls/signal_tls_bg.wasm`: TLS 1.3 pinned to Signal's roots (tls/). */
	tls: WasmSource;
};

export type Runtime = {
	connect?: Connect;
	wasm?: Partial<WasmModules>;
	/** User-Agent for REST requests to Signal. */
	userAgent?: string;
};

const runtime: Required<Pick<Runtime, "userAgent">> & Runtime = { userAgent: "signal-edge", wasm: {} };

/** Sets (or overrides) the host functions. Call before the first Signal operation. */
export function configure(r: Runtime): void {
	if (r.connect) runtime.connect = r.connect;
	if (r.wasm) runtime.wasm = { ...runtime.wasm, ...r.wasm };
	if (r.userAgent) runtime.userAgent = r.userAgent;
}

export function hostConnect(): Connect {
	if (!runtime.connect) throw new Error("signal-edge: no socket connector; import \"signal-edge/workers\" or call configure({ connect })");
	return runtime.connect;
}

export function wasmModule(name: keyof WasmModules): WasmSource {
	const m = runtime.wasm?.[name];
	if (!m) throw new Error(`signal-edge: no ${name} WASM module; import "signal-edge/workers" or call configure({ wasm: { ${name} } })`);
	return m;
}

export function userAgent(): string {
	return runtime.userAgent;
}
