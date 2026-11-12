// TURN client (RFC 8656) over TCP: the only media path a Worker has (no UDP). The server relays UDP
// between its allocation and the peers; we reach it with one TCP connection carrying STUN messages
// and ChannelData frames (padded to 4 bytes, RFC 8656 §12.5).

import { hostConnect, type RawSocket } from "../runtime.js";
import { ByteQueue, concat } from "../util/bytes.js";
import { withDeadline } from "../util/deadline.js";
import {
	ATTR,
	CLASS,
	METHOD,
	addressKey,
	attr,
	attrString,
	decodeStun,
	encodeStun,
	errorCode,
	longTermKey,
	newTransactionId,
	readU16,
	readU32,
	readXorAddress,
	value,
	xorAddress,
	type Address,
	type ParsedStun,
} from "./stun.js";

export type TurnServer = { host: string; port: number; username: string; password: string };

/** One entry of GET /v2/calling/relays (Signal-Server CallRoutingControllerV2). */
export type IceServerGroup = { username: string; password: string; urls?: string[]; urlsWithIps?: string[]; hostname?: string; ttl?: number };

export type TurnEvents = {
	/** A datagram a peer sent to our relayed address. */
	onData(peer: Address, data: Uint8Array): void;
	/** The connection closed (or failed); the allocation is gone. */
	onClose(error?: unknown): void;
};

const REQUEST_TIMEOUT_MS = 8_000;
const CONNECT_TIMEOUT_MS = 8_000;
const PERMISSION_REFRESH_MS = 240_000; // permissions last 300 s
const CHANNEL_REFRESH_MS = 480_000; // channel bindings last 600 s
const MAX_FRAME = 64 * 1024;

/**
 * TCP TURN servers from Signal's relay list, in the order to try them: explicit `transport=tcp`
 * URLs first (the IP form, then by name), then TCP to the hosts of the UDP ones (TURN servers
 * normally listen on both). `turns:` (TLS) URLs are skipped: the runtime connector is plain TCP.
 */
export function turnServers(groups: IceServerGroup[]): TurnServer[] {
	const tcp: TurnServer[] = [];
	const fallback: TurnServer[] = [];
	const seen = new Set<string>();
	for (const g of groups) {
		for (const url of [...(g.urlsWithIps ?? []), ...(g.urls ?? [])]) {
			const m = /^turn:(\[[0-9a-fA-F:.]+\]|[^:?]+)(?::(\d+))?(?:\?transport=(udp|tcp))?$/.exec(url.trim());
			if (!m) continue;
			const host = m[1]!.replace(/^\[|\]$/g, "");
			const port = m[2] ? Number(m[2]) : 3478;
			const key = `${host}|${port}`;
			if (seen.has(key)) continue;
			seen.add(key);
			(m[3] === "tcp" ? tcp : fallback).push({ host, port, username: g.username, password: g.password });
		}
	}
	return [...tcp, ...fallback];
}

type Pending = { resolve: (m: ParsedStun) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> };

export class TurnClient {
	/** Our relayed transport address: the candidate peers send to. */
	relayed!: Address;
	/** The address the server saw us connect from. */
	mapped?: Address;
	readonly server: TurnServer;

	#socket: RawSocket;
	#writer: WritableStreamDefaultWriter<Uint8Array>;
	#writes: Promise<void> = Promise.resolve();
	#events: TurnEvents;
	#pending = new Map<string, Pending>();
	#realm?: string;
	#nonce?: string;
	#key?: Uint8Array;
	#closed = false;
	#timers = new Set<ReturnType<typeof setTimeout>>();
	#permissions = new Map<string, Promise<boolean>>();
	#channels = new Map<string, number>();
	#channelPeers = new Map<number, Address>();
	#nextChannel = 0x4000;

	private constructor(socket: RawSocket, server: TurnServer, events: TurnEvents) {
		this.#socket = socket;
		this.server = server;
		this.#events = events;
		this.#writer = socket.writable.getWriter();
	}

	/** Connects to `server` and allocates a relayed UDP address. */
	static async open(server: TurnServer, events: TurnEvents, timeoutMs = CONNECT_TIMEOUT_MS): Promise<TurnClient> {
		const socket = await hostConnect()(server.host, server.port);
		const stop = () => void socket.close().catch(() => {});
		await withDeadline(() => socket.opened, timeoutMs, undefined, `TURN connect ${server.host}:${server.port}`, stop);
		const client = new TurnClient(socket, server, events);
		void client.#readLoop();
		try {
			await client.#allocate();
		} catch (e) {
			client.close();
			throw e;
		}
		return client;
	}

	/** Tries each server in turn; the first allocation wins. */
	static async openAny(servers: TurnServer[], events: TurnEvents, timeoutMs = CONNECT_TIMEOUT_MS): Promise<TurnClient> {
		const errors: string[] = [];
		for (const s of servers) {
			try {
				return await TurnClient.open(s, events, timeoutMs);
			} catch (e) {
				errors.push(`${s.host}:${s.port}: ${e instanceof Error ? e.message : String(e)}`);
			}
		}
		throw new Error(`no TURN server reachable over TCP (${errors.join("; ") || "none offered"})`);
	}

	get closed(): boolean {
		return this.#closed;
	}

	/**
	 * Lets `ip` send to our relayed address (and us to it). Each address gets its own request, so a
	 * server refusing one (e.g. a private address) doesn't take the others with it. Resolves false
	 * when refused.
	 */
	permit(ip: string): Promise<boolean> {
		let p = this.#permissions.get(ip);
		if (!p) {
			p = this.#createPermission(ip);
			this.#permissions.set(ip, p);
			p.then((ok) => {
				if (!ok) this.#permissions.delete(ip);
				else this.#every(PERMISSION_REFRESH_MS, () => this.#createPermission(ip));
			});
		}
		return p;
	}

	/**
	 * Sends a datagram to `peer` through the relay: as ChannelData once a channel is bound (four
	 * bytes of overhead), else as a Send indication while the binding is being made.
	 */
	send(peer: Address, data: Uint8Array): Promise<void> {
		if (this.#closed) return Promise.resolve();
		const key = addressKey(peer);
		const channel = this.#channels.get(key);
		if (channel !== undefined && channel > 0) {
			const pad = (4 - (data.length % 4)) % 4;
			const head = new Uint8Array([channel >> 8, channel & 0xff, data.length >> 8, data.length & 0xff]);
			return this.#write(concat(head, data, new Uint8Array(pad)));
		}
		if (channel === undefined) void this.#bind(peer);
		const txId = newTransactionId();
		const attrs: [number, Uint8Array][] = [
			[ATTR.XOR_PEER_ADDRESS, xorAddress(peer, txId)],
			[ATTR.DATA, data],
		];
		return encodeStun({ method: METHOD.SEND, cls: CLASS.INDICATION, txId, attrs }).then((m) => this.#write(m));
	}

	close(): void {
		this.#close();
	}

	#close(error?: unknown): void {
		if (this.#closed) return;
		this.#closed = true;
		for (const t of this.#timers) clearTimeout(t);
		this.#timers.clear();
		for (const p of this.#pending.values()) {
			clearTimeout(p.timer);
			p.reject(new Error("TURN connection closed"));
		}
		this.#pending.clear();
		// Best effort: a zero-lifetime Refresh frees the allocation now instead of at expiry.
		if (this.#key) {
			void this.#authed(METHOD.REFRESH, [[ATTR.LIFETIME, value.u32(0)]])
				.then((m) => this.#write(m))
				.catch(() => {})
				.finally(() => void this.#socket.close().catch(() => {}));
		} else void this.#socket.close().catch(() => {});
		this.#events.onClose(error);
	}

	// --- requests ---

	async #allocate(): Promise<void> {
		const attrs: [number, Uint8Array][] = [[ATTR.REQUESTED_TRANSPORT, value.udp()]];
		const res = await this.#request(METHOD.ALLOCATE, attrs);
		const txId = res.txId;
		const relayed = attr(res, ATTR.XOR_RELAYED_ADDRESS);
		const r = relayed && readXorAddress(relayed, txId);
		if (!r) throw new Error("TURN allocate: no relayed address");
		this.relayed = r;
		const mapped = attr(res, ATTR.XOR_MAPPED_ADDRESS);
		this.mapped = mapped && readXorAddress(mapped, txId);
		const lifetime = attr(res, ATTR.LIFETIME);
		const seconds = lifetime && lifetime.length >= 4 ? readU32(lifetime, 0) : 600;
		this.#every(Math.max(30, seconds - 60) * 1000, async () => {
			await this.#request(METHOD.REFRESH, [[ATTR.LIFETIME, value.u32(seconds)]]);
			return true;
		});
	}

	async #createPermission(ip: string): Promise<boolean> {
		try {
			await this.#request(METHOD.CREATE_PERMISSION, [[ATTR.XOR_PEER_ADDRESS, { peer: { ip, port: 0 } }]]);
			return true;
		} catch (e) {
			if (!this.#closed) console.warn(`TURN permission for ${ip} refused: ${e instanceof Error ? e.message : e}`);
			return false;
		}
	}

	async #bind(peer: Address): Promise<void> {
		const key = addressKey(peer);
		if (this.#channels.has(key) || this.#nextChannel > 0x7ffe) return;
		const channel = this.#nextChannel++;
		this.#channels.set(key, -1); // binding in progress: keep using Send indications
		const bind = async () => {
			await this.#request(METHOD.CHANNEL_BIND, [
				[ATTR.CHANNEL_NUMBER, value.channel(channel)],
				[ATTR.XOR_PEER_ADDRESS, { peer }],
			]);
			return true;
		};
		try {
			await bind();
			this.#channels.set(key, channel);
			this.#channelPeers.set(channel, peer);
			this.#every(CHANNEL_REFRESH_MS, bind);
		} catch (e) {
			if (!this.#closed) console.warn(`TURN channel bind for ${key} failed: ${e instanceof Error ? e.message : e}`);
			// Stays on Send indications (-1 keeps us from retrying on every packet).
		}
	}

	/** Runs `fn` every `ms` until the client closes; a failure closes it (the allocation is lost). */
	#every(ms: number, fn: () => Promise<boolean>): void {
		const tick = () => {
			const t = setTimeout(() => {
				this.#timers.delete(t);
				if (this.#closed) return;
				fn().then(
					() => tick(),
					(e) => {
						console.warn("TURN refresh failed", e);
						this.#fail(e);
					},
				);
			}, ms);
			this.#timers.add(t);
		};
		tick();
	}

	/** A request; with credentials once the server has told us its realm and nonce (401, 438). */
	async #request(method: number, attrs: [number, Uint8Array | { peer: Address }][], attempt = 0): Promise<ParsedStun> {
		const txId = newTransactionId();
		const resolved = attrs.map(([t, v]): [number, Uint8Array] => [t, v instanceof Uint8Array ? v : xorAddress(v.peer, txId)]);
		const msg = this.#key ? await this.#authed(method, resolved, txId) : await encodeStun({ method, cls: CLASS.REQUEST, txId, attrs: resolved });
		const res = await this.#transact(txId, msg);
		if (res.cls === CLASS.SUCCESS) return res;
		const err = errorCode(res);
		if (attempt < 2 && (err?.code === 401 || err?.code === 438)) {
			const realm = attrString(res, ATTR.REALM);
			const nonce = attrString(res, ATTR.NONCE);
			if (nonce) {
				if (realm) this.#realm = realm;
				this.#nonce = nonce;
				if (this.#realm) this.#key = longTermKey(this.server.username, this.#realm, this.server.password);
				return this.#request(method, attrs, attempt + 1);
			}
		}
		throw new Error(`TURN ${methodName(method)}: ${err ? `${err.code} ${err.reason}` : "error response"}`);
	}

	#authed(method: number, attrs: [number, Uint8Array][], txId = newTransactionId()): Promise<Uint8Array> {
		return encodeStun(
			{
				method,
				cls: CLASS.REQUEST,
				txId,
				attrs: [...attrs, [ATTR.USERNAME, value.string(this.server.username)], [ATTR.REALM, value.string(this.#realm!)], [ATTR.NONCE, value.string(this.#nonce!)]],
			},
			{ integrityKey: this.#key },
		);
	}

	#transact(txId: Uint8Array, msg: Uint8Array): Promise<ParsedStun> {
		if (this.#closed) return Promise.reject(new Error("TURN connection closed"));
		const id = hex(txId);
		return new Promise<ParsedStun>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.#pending.delete(id);
				reject(new Error("TURN request timed out"));
			}, REQUEST_TIMEOUT_MS);
			this.#pending.set(id, { resolve, reject, timer });
			this.#write(msg).catch((e) => {
				clearTimeout(timer);
				this.#pending.delete(id);
				reject(e instanceof Error ? e : new Error(String(e)));
			});
		});
	}

	// --- the connection ---

	#write(bytes: Uint8Array): Promise<void> {
		this.#writes = this.#writes.then(() => this.#writer.write(bytes)).catch((e) => this.#fail(e));
		return this.#writes;
	}

	#fail(e: unknown): void {
		this.#close(e);
	}

	async #readLoop(): Promise<void> {
		const q = new ByteQueue(this.#socket.readable);
		try {
			for (;;) {
				const head = await q.take(4);
				if ((head[0]! & 0xc0) === 0) {
					const len = readU16(head, 2);
					if (len > MAX_FRAME) throw new Error("TURN: oversized STUN message");
					const m = decodeStun(concat(head, await q.take(16 + len)));
					if (m) this.#onStun(m);
				} else if ((head[0]! & 0xc0) === 0x40) {
					const channel = readU16(head, 0);
					const len = readU16(head, 2);
					const data = await q.take(len + ((4 - (len % 4)) % 4));
					const peer = this.#channelPeers.get(channel);
					if (peer) this.#events.onData(peer, data.subarray(0, len));
				} else throw new Error("TURN: unexpected framing");
			}
		} catch (e) {
			q.cancel();
			this.#fail(e);
		}
	}

	#onStun(m: ParsedStun): void {
		if (m.cls === CLASS.SUCCESS || m.cls === CLASS.ERROR) {
			const id = hex(m.txId);
			const p = this.#pending.get(id);
			if (!p) return;
			this.#pending.delete(id);
			clearTimeout(p.timer);
			p.resolve(m);
			return;
		}
		if (m.cls === CLASS.INDICATION && m.method === METHOD.DATA) {
			const peerAttr = attr(m, ATTR.XOR_PEER_ADDRESS);
			const peer = peerAttr && readXorAddress(peerAttr, m.txId);
			const data = attr(m, ATTR.DATA);
			if (peer && data) this.#events.onData(peer, data);
		}
	}
}

function methodName(m: number): string {
	return Object.entries(METHOD).find(([, v]) => v === m)?.[0]?.toLowerCase() ?? `method ${m}`;
}

function hex(b: Uint8Array): string {
	return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
