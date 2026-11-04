import { hostConnect, wasmModule, type RawSocket } from "../runtime.js";
import { TlsClient, initSync } from "../vendor/signal-tls/signal_tls.js";

let ready = false;
function initTls(): void {
	if (ready) return;
	initSync({ module: wasmModule("tls") });
	ready = true;
}

/**
 * TLS 1.3 over a raw TCP socket (from the runtime's `connect`), trusting only Signal's root CAs (see tls/src/lib.rs).
 * `readable` yields decrypted application data; `write` encrypts and sends.
 */
export class TlsSocket {
	readonly readable: ReadableStream<Uint8Array>;
	#tls: TlsClient;
	#writer: WritableStreamDefaultWriter<Uint8Array>;
	#socket: RawSocket;
	#closed = false;
	/** Socket writes run one after another, so records from write() and the read pump never interleave. */
	#writes: Promise<void> = Promise.resolve();

	private constructor(tls: TlsClient, socket: RawSocket, early: Uint8Array[]) {
		this.#tls = tls;
		this.#socket = socket;
		this.#writer = socket.writable.getWriter();
		const reader = socket.readable.getReader();
		const pending = early;
		this.readable = new ReadableStream<Uint8Array>({
			pull: async (controller) => {
				if (pending.length) {
					controller.enqueue(pending.shift()!);
					return;
				}
				for (;;) {
					const { value, done } = await reader.read();
					if (done || this.#closed) {
						controller.close();
						return;
					}
					const plaintext = this.#receive(value);
					await this.#flush();
					if (plaintext.length) {
						controller.enqueue(plaintext);
						return;
					}
					if (this.#tls.peer_closed) {
						controller.close();
						return;
					}
				}
			},
			cancel: () => this.close(),
		});
	}

	static async connect(hostname: string, port = 443): Promise<TlsSocket> {
		initTls();
		const socket = await hostConnect()(hostname, port);
		await socket.opened;
		const tls = new TlsClient(hostname);
		const writer = socket.writable.getWriter();
		const reader = socket.readable.getReader();
		const early: Uint8Array[] = [];
		try {
			await write(writer, tls.outgoing());
			while (tls.handshaking) {
				const { value, done } = await reader.read();
				if (done) throw new Error(`TLS: ${hostname} closed during handshake`);
				let plaintext: Uint8Array;
				try {
					plaintext = tls.receive(value);
				} finally {
					// Send our reply, or the alert explaining why we are giving up.
					await write(writer, tls.outgoing()).catch(() => {});
				}
				if (plaintext.length) early.push(plaintext);
			}
		} catch (e) {
			tls.free();
			await socket.close().catch(() => {});
			throw e;
		}
		writer.releaseLock();
		reader.releaseLock();
		return new TlsSocket(tls, socket, early);
	}

	async write(data: Uint8Array): Promise<void> {
		// rustls buffers a bounded amount of plaintext, so large writes go out in pieces.
		let off = 0;
		do {
			if (this.#closed) throw new Error("TLS: socket is closed");
			const n = this.#tls.send(data.subarray(off));
			const out = this.#tls.outgoing();
			if (n === 0 && out.length === 0) throw new Error("TLS: send buffer full and nothing to flush");
			off += n;
			await this.#enqueue(out);
		} while (off < data.length);
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		try {
			this.#tls.close();
			await this.#flush();
		} catch {
			// Best effort: the peer may already be gone.
		}
		this.#tls.free();
		await this.#socket.close().catch(() => {});
	}

	#receive(data: Uint8Array): Uint8Array {
		try {
			return this.#tls.receive(data);
		} catch (e) {
			void this.#flush().catch(() => {});
			throw e;
		}
	}

	// outgoing() is taken synchronously and queued in the same tick, so records keep their order.
	#flush(): Promise<void> {
		return this.#enqueue(this.#tls.outgoing());
	}

	#enqueue(bytes: Uint8Array): Promise<void> {
		if (!bytes.length) return this.#writes;
		this.#writes = this.#writes.then(() => write(this.#writer, bytes));
		return this.#writes;
	}
}

// On the deployed edge a single socket write above 64 KiB drops the connection ("Network
// connection lost"); local workerd doesn't. Write at most one TLS record's worth at a time.
const MAX_SOCKET_WRITE = 16 * 1024;

async function write(writer: WritableStreamDefaultWriter<Uint8Array>, bytes: Uint8Array): Promise<void> {
	for (let off = 0; off < bytes.length; off += MAX_SOCKET_WRITE) {
		await writer.write(bytes.subarray(off, off + MAX_SOCKET_WRITE));
	}
}
