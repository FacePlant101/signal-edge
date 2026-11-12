// STUN (RFC 8489) messages with the TURN (RFC 8656) and ICE (RFC 8445) attributes a 1:1 call needs:
// encoding, parsing, MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT (CRC-32). Test vectors: RFC 5769.

import { concat, enc, randomBytes, timingSafeEqual } from "../util/bytes.js";

export const MAGIC_COOKIE = 0x2112a442;

export const METHOD = { BINDING: 0x001, ALLOCATE: 0x003, REFRESH: 0x004, SEND: 0x006, DATA: 0x007, CREATE_PERMISSION: 0x008, CHANNEL_BIND: 0x009 } as const;
export const CLASS = { REQUEST: 0, INDICATION: 1, SUCCESS: 2, ERROR: 3 } as const;

export const ATTR = {
	USERNAME: 0x0006,
	MESSAGE_INTEGRITY: 0x0008,
	ERROR_CODE: 0x0009,
	CHANNEL_NUMBER: 0x000c,
	LIFETIME: 0x000d,
	XOR_PEER_ADDRESS: 0x0012,
	DATA: 0x0013,
	REALM: 0x0014,
	NONCE: 0x0015,
	XOR_RELAYED_ADDRESS: 0x0016,
	REQUESTED_TRANSPORT: 0x0019,
	XOR_MAPPED_ADDRESS: 0x0020,
	PRIORITY: 0x0024,
	USE_CANDIDATE: 0x0025,
	SOFTWARE: 0x8022,
	FINGERPRINT: 0x8028,
	ICE_CONTROLLED: 0x8029,
	ICE_CONTROLLING: 0x802a,
	/** WebRTC's renomination (goog): a nomination counter instead of USE-CANDIDATE. */
	NOMINATION: 0xc001,
} as const;

/** An IP address and port; `ip` is dotted IPv4 or eight-group IPv6 as formatIp writes it. */
export type Address = { ip: string; port: number };

export type StunMessage = {
	method: number;
	cls: number;
	/** 12-byte transaction id. */
	txId: Uint8Array;
	attrs: [type: number, value: Uint8Array][];
};

export function addressKey(a: Address): string {
	return `${a.ip}|${a.port}`;
}

// --- IP addresses ---

export function parseIp(ip: string): Uint8Array | undefined {
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
		const parts = ip.split(".").map(Number);
		return parts.every((p) => p <= 255) ? new Uint8Array(parts) : undefined;
	}
	if (!ip.includes(":") || ip.includes("%")) return undefined;
	const [head, tail, extra] = ip.split("::");
	if (extra !== undefined) return undefined;
	const groups = (s: string | undefined) => (s ? s.split(":") : []);
	const h = groups(head);
	const t = tail === undefined ? [] : groups(tail);
	const missing = 8 - h.length - t.length;
	if (tail === undefined ? missing !== 0 : missing < 1) return undefined;
	const all = [...h, ...Array<string>(tail === undefined ? 0 : missing).fill("0"), ...t];
	const out = new Uint8Array(16);
	for (let i = 0; i < 8; i++) {
		if (!/^[0-9a-fA-F]{1,4}$/.test(all[i]!)) return undefined;
		const v = parseInt(all[i]!, 16);
		out[2 * i] = v >> 8;
		out[2 * i + 1] = v & 0xff;
	}
	return out;
}

export function formatIp(b: Uint8Array): string {
	if (b.length === 4) return Array.from(b).join(".");
	const groups: string[] = [];
	for (let i = 0; i < 16; i += 2) groups.push(((b[i]! << 8) | b[i + 1]!).toString(16));
	return groups.join(":");
}

/** The canonical form of an IP string (as formatIp writes it), or undefined if it isn't one. */
export function normalizeIp(ip: string): string | undefined {
	const b = parseIp(ip);
	return b && formatIp(b);
}

// --- encoding ---

function u16(n: number): Uint8Array {
	return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}
function u32(n: number): Uint8Array {
	return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
export function readU16(b: Uint8Array, off: number): number {
	return (b[off]! << 8) | b[off + 1]!;
}
export function readU32(b: Uint8Array, off: number): number {
	return ((b[off]! << 24) | (b[off + 1]! << 16) | (b[off + 2]! << 8) | b[off + 3]!) >>> 0;
}

function messageType(method: number, cls: number): number {
	return (method & 0x000f) | ((method & 0x0070) << 1) | ((method & 0x0f80) << 2) | ((cls & 1) << 4) | ((cls & 2) << 7);
}

export function newTransactionId(): Uint8Array {
	return randomBytes(12);
}

export function xorAddress(a: Address, txId: Uint8Array): Uint8Array {
	const ip = parseIp(a.ip);
	if (!ip) throw new Error(`stun: bad IP ${a.ip}`);
	const mask = concat(u32(MAGIC_COOKIE), txId);
	const x = ip.map((v, i) => v ^ mask[i]!);
	return concat(new Uint8Array([0, ip.length === 4 ? 1 : 2]), u16(a.port ^ (MAGIC_COOKIE >>> 16)), x);
}

export function readXorAddress(v: Uint8Array, txId: Uint8Array): Address | undefined {
	if (v.length < 8) return undefined;
	const family = v[1];
	const len = family === 1 ? 4 : family === 2 ? 16 : 0;
	if (!len || v.length < 4 + len) return undefined;
	const mask = concat(u32(MAGIC_COOKIE), txId);
	const ip = v.subarray(4, 4 + len).map((b, i) => b ^ mask[i]!);
	return { ip: formatIp(ip), port: readU16(v, 2) ^ (MAGIC_COOKIE >>> 16) };
}

function attribute(type: number, value: Uint8Array): Uint8Array {
	const pad = (4 - (value.length % 4)) % 4;
	return concat(u16(type), u16(value.length), value, new Uint8Array(pad));
}

export type EncodeOptions = {
	/** Adds MESSAGE-INTEGRITY with this key (the ICE password, or the TURN long-term key). */
	integrityKey?: Uint8Array;
	/** Adds FINGERPRINT (ICE checks carry it; TURN doesn't need it). */
	fingerprint?: boolean;
};

export async function encodeStun(m: StunMessage, opts: EncodeOptions = {}): Promise<Uint8Array> {
	let body = concat(...m.attrs.map(([t, v]) => attribute(t, v)));
	const header = (extra: number) => concat(u16(messageType(m.method, m.cls)), u16(body.length + extra), u32(MAGIC_COOKIE), m.txId);
	if (opts.integrityKey) {
		const mac = await hmacSha1(opts.integrityKey, concat(header(24), body));
		body = concat(body, attribute(ATTR.MESSAGE_INTEGRITY, mac));
	}
	if (opts.fingerprint) {
		const crc = (crc32(concat(header(8), body)) ^ 0x5354554e) >>> 0;
		body = concat(body, attribute(ATTR.FINGERPRINT, u32(crc)));
	}
	return concat(header(0), body);
}

// --- decoding ---

export type ParsedStun = StunMessage & {
	raw: Uint8Array;
	/** Offset of the MESSAGE-INTEGRITY attribute header, if present. */
	integrityAt?: number;
	/** Offset of the FINGERPRINT attribute header, if present. */
	fingerprintAt?: number;
};

/** True when `b` looks like a STUN message (top two bits zero and the magic cookie). */
export function isStun(b: Uint8Array): boolean {
	return b.length >= 20 && (b[0]! & 0xc0) === 0 && readU32(b, 4) === MAGIC_COOKIE;
}

export function decodeStun(b: Uint8Array): ParsedStun | undefined {
	if (!isStun(b)) return undefined;
	const len = readU16(b, 2);
	if (len % 4 || b.length < 20 + len) return undefined;
	const raw = b.subarray(0, 20 + len);
	const type = readU16(b, 0);
	const method = (type & 0x000f) | ((type & 0x00e0) >> 1) | ((type & 0x3e00) >> 2);
	const cls = ((type & 0x0010) >> 4) | ((type & 0x0100) >> 7);
	const out: ParsedStun = { method, cls, txId: raw.slice(8, 20), attrs: [], raw };
	let off = 20;
	while (off + 4 <= raw.length) {
		const t = readU16(raw, off);
		const l = readU16(raw, off + 2);
		if (off + 4 + l > raw.length) return undefined;
		// Attributes after MESSAGE-INTEGRITY other than FINGERPRINT aren't covered by it: ignore them.
		if (out.integrityAt !== undefined && t !== ATTR.FINGERPRINT) {
			off += 4 + l + ((4 - (l % 4)) % 4);
			continue;
		}
		if (t === ATTR.MESSAGE_INTEGRITY) out.integrityAt = off;
		if (t === ATTR.FINGERPRINT) out.fingerprintAt = off;
		out.attrs.push([t, raw.subarray(off + 4, off + 4 + l)]);
		off += 4 + l + ((4 - (l % 4)) % 4);
		if (t === ATTR.FINGERPRINT) break;
	}
	return out;
}

export function attr(m: StunMessage, type: number): Uint8Array | undefined {
	return m.attrs.find(([t]) => t === type)?.[1];
}

export function attrString(m: StunMessage, type: number): string | undefined {
	const v = attr(m, type);
	return v && new TextDecoder().decode(v);
}

export function errorCode(m: StunMessage): { code: number; reason: string } | undefined {
	const v = attr(m, ATTR.ERROR_CODE);
	if (!v || v.length < 4) return undefined;
	return { code: (v[2]! & 7) * 100 + v[3]!, reason: new TextDecoder().decode(v.subarray(4)) };
}

export async function checkIntegrity(m: ParsedStun, key: Uint8Array): Promise<boolean> {
	const at = m.integrityAt;
	if (at === undefined) return false;
	const given = m.raw.subarray(at + 4, at + 24);
	const head = m.raw.slice(0, at);
	const len = at + 24 - 20;
	head[2] = len >> 8;
	head[3] = len & 0xff;
	return timingSafeEqual(await hmacSha1(key, head), given);
}

export function checkFingerprint(m: ParsedStun): boolean {
	const at = m.fingerprintAt;
	if (at === undefined) return false;
	return ((crc32(m.raw.subarray(0, at)) ^ 0x5354554e) >>> 0) === readU32(m.raw, at + 4);
}

// --- attribute values ---

export const value = {
	u32,
	string: (s: string) => enc.encode(s),
	/** ICE-CONTROLLING / ICE-CONTROLLED tie-breaker. */
	tieBreaker: (n: bigint) => {
		const out = new Uint8Array(8);
		new DataView(out.buffer).setBigUint64(0, n);
		return out;
	},
	/** REQUESTED-TRANSPORT: UDP. */
	udp: () => new Uint8Array([17, 0, 0, 0]),
	channel: (n: number) => concat(u16(n), u16(0)),
};

/** TURN long-term credential key: MD5(username ":" realm ":" password). */
export function longTermKey(username: string, realm: string, password: string): Uint8Array {
	return md5(enc.encode(`${username}:${realm}:${password}`));
}

// --- primitives ---

const hmacKeys = new Map<string, Promise<CryptoKey>>();

async function hmacSha1(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const id = Array.from(key, (b) => b.toString(16).padStart(2, "0")).join("");
	let k = hmacKeys.get(id);
	if (!k) {
		if (hmacKeys.size > 64) hmacKeys.clear();
		k = crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
		hmacKeys.set(id, k);
	}
	return new Uint8Array(await crypto.subtle.sign("HMAC", await k, data));
}

let crcTable: Uint32Array | undefined;

export function crc32(b: Uint8Array): number {
	if (!crcTable) {
		crcTable = new Uint32Array(256);
		for (let n = 0; n < 256; n++) {
			let c = n;
			for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
			crcTable[n] = c >>> 0;
		}
	}
	let c = 0xffffffff;
	for (let i = 0; i < b.length; i++) c = crcTable[(c ^ b[i]!) & 0xff]! ^ (c >>> 8);
	return (c ^ 0xffffffff) >>> 0;
}

// MD5 (RFC 1321): only for the TURN long-term key, which the protocol defines with it.
const MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

export function md5(input: Uint8Array): Uint8Array {
	const bitLen = input.length * 8;
	const padded = new Uint8Array((((input.length + 8) >> 6) + 1) << 6);
	padded.set(input);
	padded[input.length] = 0x80;
	const dv = new DataView(padded.buffer);
	dv.setUint32(padded.length - 8, bitLen >>> 0, true);
	dv.setUint32(padded.length - 4, Math.floor(bitLen / 2 ** 32), true);
	let a0 = 0x67452301,
		b0 = 0xefcdab89,
		c0 = 0x98badcfe,
		d0 = 0x10325476;
	const m = new Uint32Array(16);
	for (let off = 0; off < padded.length; off += 64) {
		for (let i = 0; i < 16; i++) m[i] = dv.getUint32(off + 4 * i, true);
		let a = a0,
			b = b0,
			c = c0,
			d = d0;
		for (let i = 0; i < 64; i++) {
			let f: number, g: number;
			if (i < 16) (f = (b & c) | (~b & d)), (g = i);
			else if (i < 32) (f = (d & b) | (~d & c)), (g = (5 * i + 1) % 16);
			else if (i < 48) (f = b ^ c ^ d), (g = (3 * i + 5) % 16);
			else (f = c ^ (b | ~d)), (g = (7 * i) % 16);
			const tmp = d;
			d = c;
			c = b;
			const x = (a + f + MD5_K[i]! + m[g]!) >>> 0;
			const s = MD5_S[(i >> 4) * 4 + (i % 4)]!;
			b = (b + ((x << s) | (x >>> (32 - s)))) >>> 0;
			a = tmp;
		}
		a0 = (a0 + a) >>> 0;
		b0 = (b0 + b) >>> 0;
		c0 = (c0 + c) >>> 0;
		d0 = (d0 + d) >>> 0;
	}
	const out = new Uint8Array(16);
	const ov = new DataView(out.buffer);
	[a0, b0, c0, d0].forEach((v, i) => ov.setUint32(4 * i, v, true));
	return out;
}
