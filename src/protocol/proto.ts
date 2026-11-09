// Minimal proto2 wire codec for the handful of Signal messages we need.
// Field numbers come from Signal's .proto files (cited per message below).

import { concat, dec, enc } from "../util/bytes.js";

type Value = number | bigint | boolean | string | Uint8Array;
type Field = [num: number, value: Value | undefined | null];

function varint(n: number | bigint): number[] {
	let v = BigInt(n);
	if (v < 0n) v &= (1n << 64n) - 1n;
	const out: number[] = [];
	do {
		let b = Number(v & 0x7fn);
		v >>= 7n;
		if (v) b |= 0x80;
		out.push(b);
	} while (v);
	return out;
}

export function encode(fields: Field[]): Uint8Array {
	const parts: Uint8Array[] = [];
	for (const [num, value] of fields) {
		if (value === undefined || value === null) continue;
		if (typeof value === "string" || value instanceof Uint8Array) {
			const bytes = typeof value === "string" ? enc.encode(value) : value;
			parts.push(new Uint8Array([...varint((num << 3) | 2), ...varint(bytes.length)]), bytes);
		} else {
			const n = typeof value === "boolean" ? Number(value) : value;
			parts.push(new Uint8Array([...varint(num << 3), ...varint(n)]));
		}
	}
	return concat(...parts);
}

/** Decoded message: field number → raw values (bigint for varints, Uint8Array for length-delimited). */
export class Decoded {
	readonly fields = new Map<number, (bigint | Uint8Array)[]>();

	constructor(buf: Uint8Array) {
		let i = 0;
		const readVarint = (): bigint => {
			let result = 0n;
			let shift = 0n;
			for (;;) {
				if (i >= buf.length) throw new Error("proto: truncated varint");
				const b = buf[i++]!;
				result |= BigInt(b & 0x7f) << shift;
				if (!(b & 0x80)) return result;
				shift += 7n;
				if (shift > 63n) throw new Error("proto: varint too long");
			}
		};
		while (i < buf.length) {
			const tag = Number(readVarint());
			const num = tag >>> 3;
			const wire = tag & 7;
			let value: bigint | Uint8Array;
			if (wire === 0) value = readVarint();
			else if (wire === 2) {
				const len = Number(readVarint());
				if (i + len > buf.length) throw new Error("proto: truncated field");
				value = buf.subarray(i, i + len);
				i += len;
			} else if (wire === 1) {
				value = buf.subarray(i, i + 8);
				i += 8;
			} else if (wire === 5) {
				value = buf.subarray(i, i + 4);
				i += 4;
			} else throw new Error(`proto: unsupported wire type ${wire}`);
			const list = this.fields.get(num);
			if (list) list.push(value);
			else this.fields.set(num, [value]);
		}
	}

	bytes(num: number): Uint8Array | undefined {
		const v = this.fields.get(num)?.at(-1);
		return v instanceof Uint8Array ? v : undefined;
	}
	string(num: number): string | undefined {
		const b = this.bytes(num);
		return b && dec.decode(b);
	}
	strings(num: number): string[] {
		return (this.fields.get(num) ?? []).filter((v) => v instanceof Uint8Array).map((v) => dec.decode(v as Uint8Array));
	}
	uint(num: number): number | undefined {
		const v = this.fields.get(num)?.at(-1);
		return typeof v === "bigint" ? Number(v) : undefined;
	}
	bigint(num: number): bigint | undefined {
		const v = this.fields.get(num)?.at(-1);
		return typeof v === "bigint" ? v : undefined;
	}
	bool(num: number): boolean | undefined {
		const v = this.uint(num);
		return v === undefined ? undefined : v !== 0;
	}
}

// --- libsignal rust/net/src/proto/chat_websocket.proto ---

export const WS_REQUEST = 1;
export const WS_RESPONSE = 2;

export type WsRequest = { verb: string; path: string; body?: Uint8Array; headers: string[]; id: bigint };
export type WsResponse = { id: bigint; status: number; message?: string; headers: string[]; body?: Uint8Array };

export function encodeWsRequest(r: WsRequest): Uint8Array {
	const req = encode([[1, r.verb], [2, r.path], [3, r.body], [4, r.id], ...r.headers.map((h): Field => [5, h])]);
	return encode([[1, WS_REQUEST], [2, req]]);
}

export function encodeWsResponse(r: WsResponse): Uint8Array {
	const res = encode([[1, r.id], [2, r.status], [3, r.message], [4, r.body], ...r.headers.map((h): Field => [5, h])]);
	return encode([[1, WS_RESPONSE], [3, res]]);
}

export function decodeWsMessage(buf: Uint8Array): { request?: WsRequest; response?: WsResponse } {
	const m = new Decoded(buf);
	const type = m.uint(1);
	if (type === WS_REQUEST) {
		const r = new Decoded(m.bytes(2) ?? new Uint8Array(0));
		return { request: { verb: r.string(1) ?? "", path: r.string(2) ?? "", body: r.bytes(3), id: r.bigint(4) ?? 0n, headers: r.strings(5) } };
	}
	if (type === WS_RESPONSE) {
		const r = new Decoded(m.bytes(3) ?? new Uint8Array(0));
		return { response: { id: r.bigint(1) ?? 0n, status: r.uint(2) ?? 0, message: r.string(3), body: r.bytes(4), headers: r.strings(5) } };
	}
	return {};
}

// --- Signal-Desktop protos/DeviceMessages.proto ---

export function decodeProvisioningAddress(buf: Uint8Array): string | undefined {
	return new Decoded(buf).string(1);
}

export function decodeProvisionEnvelope(buf: Uint8Array): { publicKey?: Uint8Array; body?: Uint8Array } {
	const m = new Decoded(buf);
	return { publicKey: m.bytes(1), body: m.bytes(2) };
}

export type ProvisionMessage = {
	aciIdentityKeyPublic?: Uint8Array;
	aciIdentityKeyPrivate?: Uint8Array;
	pniIdentityKeyPublic?: Uint8Array;
	pniIdentityKeyPrivate?: Uint8Array;
	aci?: string;
	pni?: string;
	number?: string;
	provisioningCode?: string;
	userAgent?: string;
	profileKey?: Uint8Array;
	readReceipts?: boolean;
	provisioningVersion?: number;
	masterKey?: Uint8Array;
	ephemeralBackupKey?: Uint8Array;
	accountEntropyPool?: string;
	mediaRootBackupKey?: Uint8Array;
	aciBinary?: Uint8Array;
	pniBinary?: Uint8Array;
	authCredentialSalt?: Uint8Array;
};

export function decodeProvisionMessage(buf: Uint8Array): ProvisionMessage {
	const m = new Decoded(buf);
	return {
		aciIdentityKeyPublic: m.bytes(1),
		aciIdentityKeyPrivate: m.bytes(2),
		number: m.string(3),
		provisioningCode: m.string(4),
		userAgent: m.string(5),
		profileKey: m.bytes(6),
		readReceipts: m.bool(7),
		aci: m.string(8),
		provisioningVersion: m.uint(9),
		pni: m.string(10),
		pniIdentityKeyPublic: m.bytes(11),
		pniIdentityKeyPrivate: m.bytes(12),
		masterKey: m.bytes(13),
		ephemeralBackupKey: m.bytes(14),
		accountEntropyPool: m.string(15),
		mediaRootBackupKey: m.bytes(16),
		aciBinary: m.bytes(17),
		pniBinary: m.bytes(18),
		authCredentialSalt: m.bytes(19),
	};
}

// --- Signal-Desktop protos/DeviceName.proto ---

export function encodeDeviceName(d: { ephemeralPublic: Uint8Array; syntheticIv: Uint8Array; ciphertext: Uint8Array }): Uint8Array {
	return encode([[1, d.ephemeralPublic], [2, d.syntheticIv], [3, d.ciphertext]]);
}
