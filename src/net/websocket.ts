import { userAgent } from "../runtime.js";
import { ByteQueue, concat, enc, randomBytes, toBase64 } from "../util/bytes.js";
import { formatRequestHead, readResponseHead } from "./http.js";
import { TlsSocket } from "./tls.js";
import { withDeadline } from "../util/deadline.js";

const OP_CONT = 0x0;
const OP_TEXT = 0x1;
const OP_BINARY = 0x2;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

const MAX_MESSAGE = 16 * 1024 * 1024;
/** Deadline for connecting, the TLS handshake and the HTTP upgrade together. */
const CONNECT_TIMEOUT_MS = 30_000;

export type WsHandlers = {
	onMessage: (data: Uint8Array) => void | Promise<void>;
	onClose: (code: number, reason: string) => void;
};

/** RFC 6455 client over TlsSocket, since a Worker's own WebSocket client can't reach Signal's CA. */
export class WsClient {
	#sock: TlsSocket;
	#closed = false;

	private constructor(sock: TlsSocket) {
		this.#sock = sock;
	}

	static async connect(host: string, path: string, headers: Record<string, string>, handlers: WsHandlers): Promise<WsClient> {
		let sock: TlsSocket | undefined;
		let stopped = false;
		return withDeadline(
			async () => {
				const s = await TlsSocket.connect(host);
				sock = s;
				if (stopped) {
					await s.close();
					throw new Error(`WebSocket: connect to ${host} stopped`);
				}
				return WsClient.#upgrade(s, host, path, headers, handlers);
			},
			CONNECT_TIMEOUT_MS,
			undefined,
			`WebSocket: connect to ${host}${path}`,
			() => {
				stopped = true;
				void sock?.close();
			},
		);
	}

	static async #upgrade(sock: TlsSocket, host: string, path: string, headers: Record<string, string>, handlers: WsHandlers): Promise<WsClient> {
		const key = toBase64(randomBytes(16));
		try {
			await sock.write(
				formatRequestHead("GET", host, path, {
					Upgrade: "websocket",
					Connection: "Upgrade",
					"Sec-WebSocket-Key": key,
					"Sec-WebSocket-Version": "13",
					"User-Agent": userAgent(),
					...headers,
				}),
			);
			const q = new ByteQueue(sock.readable);
			const { status, headers: res } = await readResponseHead(q);
			if (status !== 101) throw new Error(`WebSocket: upgrade to ${host}${path} failed with HTTP ${status}`);
			const digest = await crypto.subtle.digest("SHA-1", enc.encode(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
			if (res.get("sec-websocket-accept") !== toBase64(new Uint8Array(digest))) {
				throw new Error("WebSocket: bad Sec-WebSocket-Accept");
			}
			const ws = new WsClient(sock);
			void ws.#readLoop(q, handlers);
			return ws;
		} catch (e) {
			await sock.close();
			throw e;
		}
	}

	send(data: Uint8Array): Promise<void> {
		return this.#frame(OP_BINARY, data);
	}

	async close(code = 1000, reason = ""): Promise<void> {
		if (this.#closed) return;
		const payload = concat(new Uint8Array([code >> 8, code & 0xff]), enc.encode(reason));
		await this.#frame(OP_CLOSE, payload).catch(() => {});
		this.#closed = true;
		await this.#sock.close();
	}

	get closed(): boolean {
		return this.#closed;
	}

	async #frame(opcode: number, payload: Uint8Array): Promise<void> {
		if (this.#closed) throw new Error("WebSocket: closed");
		const n = payload.length;
		const lenBytes = n < 126 ? [0x80 | n] : n < 65536 ? [0x80 | 126, n >> 8, n & 0xff] : [0x80 | 127, 0, 0, 0, 0, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
		const mask = randomBytes(4);
		const masked = new Uint8Array(n);
		for (let i = 0; i < n; i++) masked[i] = payload[i]! ^ mask[i & 3]!;
		await this.#sock.write(concat(new Uint8Array([0x80 | opcode, ...lenBytes]), mask, masked));
	}

	async #readLoop(q: ByteQueue, handlers: WsHandlers): Promise<void> {
		let code = 1006;
		let reason = "connection lost";
		let fragments: Uint8Array[] = [];
		let fragmentBytes = 0;
		try {
			for (;;) {
				const [b0, b1] = await q.take(2);
				const fin = (b0! & 0x80) !== 0;
				const opcode = b0! & 0x0f;
				let len = b1! & 0x7f;
				if (len === 126) {
					const b = await q.take(2);
					len = (b[0]! << 8) | b[1]!;
				} else if (len === 127) {
					const b = await q.take(8);
					len = Number(new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0));
				}
				if (len > MAX_MESSAGE) throw new Error("WebSocket: frame too large");
				const mask = b1! & 0x80 ? await q.take(4) : undefined;
				const payload = await q.take(len);
				if (mask) for (let i = 0; i < len; i++) payload[i]! ^= mask[i & 3]!;

				if (opcode === OP_PING) {
					await this.#frame(OP_PONG, payload);
				} else if (opcode === OP_PONG) {
					// Unsolicited pongs are allowed; nothing to do.
				} else if (opcode === OP_CLOSE) {
					code = payload.length >= 2 ? (payload[0]! << 8) | payload[1]! : 1005;
					reason = new TextDecoder().decode(payload.subarray(2));
					if (!this.#closed) await this.#frame(OP_CLOSE, payload.subarray(0, 2)).catch(() => {});
					break;
				} else if (opcode === OP_BINARY || opcode === OP_TEXT || opcode === OP_CONT) {
					fragmentBytes += payload.length;
					if (fragmentBytes > MAX_MESSAGE) throw new Error("WebSocket: message too large");
					fragments.push(payload);
					if (fin) {
						const message = fragments.length === 1 ? fragments[0]! : concat(...fragments);
						fragments = [];
						fragmentBytes = 0;
						await handlers.onMessage(message);
					}
				} else {
					throw new Error(`WebSocket: unknown opcode ${opcode}`);
				}
			}
		} catch (e) {
			if (!this.#closed) reason = String(e);
		} finally {
			q.cancel();
			if (!this.#closed) {
				this.#closed = true;
				await this.#sock.close();
			}
			handlers.onClose(code, reason);
		}
	}
}
