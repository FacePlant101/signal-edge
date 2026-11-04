import { WsClient } from "../net/websocket.js";
import { decodeWsMessage, encodeWsRequest, encodeWsResponse, type WsRequest, type WsResponse } from "./proto.js";

export const CHAT_HOST = "chat.signal.org";
const KEEPALIVE_MS = 30_000;
const REQUEST_TIMEOUT_MS = 30_000;

export type SignalSocketHandlers = {
	/** Server-initiated request; return the HTTP status to acknowledge with. */
	onRequest: (req: WsRequest) => number | Promise<number>;
	onClose: (code: number, reason: string) => void;
};

/**
 * Signal's WebSocket protocol: every frame is a WebSocketMessage carrying an
 * HTTP-like request or response, matched by id. The server sends requests
 * (e.g. PUT /v1/address on the provisioning socket) and we ack them; we send
 * GET /v1/keepalive so idle sockets stay open.
 */
export class SignalSocket {
	#ws!: WsClient;
	#nextId = 1n;
	#pending = new Map<bigint, { resolve: (r: WsResponse) => void; reject: (e: Error) => void }>();
	#keepalive?: ReturnType<typeof setInterval>;

	static async connect(path: string, handlers: SignalSocketHandlers, headers: Record<string, string> = {}): Promise<SignalSocket> {
		const s = new SignalSocket();
		s.#ws = await WsClient.connect(CHAT_HOST, path, headers, {
			onMessage: (data) => s.#onMessage(data, handlers),
			onClose: (code, reason) => {
				if (s.#keepalive) clearInterval(s.#keepalive);
				for (const p of s.#pending.values()) p.reject(new Error(`socket closed: ${code} ${reason}`));
				s.#pending.clear();
				handlers.onClose(code, reason);
			},
		});
		s.#keepalive = setInterval(() => {
			s.request("GET", "/v1/keepalive").catch(() => {});
		}, KEEPALIVE_MS);
		return s;
	}

	request(verb: string, path: string, body?: Uint8Array, headers: string[] = []): Promise<WsResponse> {
		const id = this.#nextId++;
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.#pending.delete(id);
				reject(new Error(`${verb} ${path} timed out`));
			}, REQUEST_TIMEOUT_MS);
			this.#pending.set(id, {
				resolve: (r) => (clearTimeout(timer), resolve(r)),
				reject: (e) => (clearTimeout(timer), reject(e)),
			});
			this.#ws.send(encodeWsRequest({ verb, path, body, headers, id })).catch((e) => {
				this.#pending.delete(id);
				clearTimeout(timer);
				reject(e);
			});
		});
	}

	close(): Promise<void> {
		if (this.#keepalive) clearInterval(this.#keepalive);
		return this.#ws.close();
	}

	get closed(): boolean {
		return this.#ws.closed;
	}

	async #onMessage(data: Uint8Array, handlers: SignalSocketHandlers): Promise<void> {
		const { request, response } = decodeWsMessage(data);
		if (response) {
			this.#pending.get(response.id)?.resolve(response);
			this.#pending.delete(response.id);
		} else if (request) {
			let status = 500;
			try {
				status = await handlers.onRequest(request);
			} finally {
				await this.#ws.send(encodeWsResponse({ id: request.id, status, message: status === 200 ? "OK" : "Error", headers: [] }));
			}
		}
	}
}
