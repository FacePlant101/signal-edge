// Call signaling on the wire: Signal's CallMessage (Signal-Desktop protos/SignalService.proto, Content
// field 3) carrying RingRTC's opaque protos (ringrtc protobuf/signaling.proto, rtp_data.proto), and
// the SRTP keys both sides derive from the signaled X25519 keys (ringrtc core/connection.rs).

import { agree } from "../protocol/crypto.js";
import { Decoded, encode } from "../protocol/proto.js";
import { concat, enc } from "../util/bytes.js";
import { SRTP_KEY_BYTES, SRTP_SALT_BYTES, type SrtpKey } from "./srtp.js";

export const OFFER_TYPE = { AUDIO: 0, VIDEO: 1 } as const;
export const HANGUP_TYPE = { NORMAL: 0, ACCEPTED: 1, DECLINED: 2, BUSY: 3, NEED_PERMISSION: 4 } as const;
export const URGENCY = { DROPPABLE: 0, HANDLE_IMMEDIATELY: 1 } as const;

export type CallMessage = {
	offer?: { id: bigint; type: number; opaque: Uint8Array };
	answer?: { id: bigint; opaque: Uint8Array };
	iceUpdates?: { id: bigint; opaque: Uint8Array }[];
	busy?: { id: bigint };
	hangup?: { id: bigint; type: number; deviceId?: number };
	destinationDeviceId?: number;
	opaque?: { data?: Uint8Array; urgency?: number };
};

export function encodeCallMessage(m: CallMessage): Uint8Array {
	return encode([
		[1, m.offer && encode([[1, m.offer.id], [3, m.offer.type], [4, m.offer.opaque]])],
		[2, m.answer && encode([[1, m.answer.id], [3, m.answer.opaque]])],
		...(m.iceUpdates ?? []).map((u): [number, Uint8Array] => [3, encode([[1, u.id], [5, u.opaque]])]),
		[5, m.busy && encode([[1, m.busy.id]])],
		[7, m.hangup && encode([[1, m.hangup.id], [2, m.hangup.type], [3, m.hangup.deviceId]])],
		[9, m.destinationDeviceId],
		[10, m.opaque && encode([[1, m.opaque.data], [2, m.opaque.urgency]])],
	]);
}

/** Content { callMessage = 3 }. */
export function contentWithCallMessage(m: CallMessage): Uint8Array {
	return encode([[3, encodeCallMessage(m)]]);
}

export function decodeCallMessage(b: Uint8Array): CallMessage {
	const d = new Decoded(b);
	const out: CallMessage = {};
	const offer = d.bytes(1);
	if (offer) {
		const o = new Decoded(offer);
		const id = o.bigint(1);
		if (id !== undefined) out.offer = { id, type: o.uint(3) ?? 0, opaque: o.bytes(4) ?? new Uint8Array(0) };
	}
	const answer = d.bytes(2);
	if (answer) {
		const a = new Decoded(answer);
		const id = a.bigint(1);
		if (id !== undefined) out.answer = { id, opaque: a.bytes(3) ?? new Uint8Array(0) };
	}
	for (const v of d.fields.get(3) ?? []) {
		if (!(v instanceof Uint8Array)) continue;
		const u = new Decoded(v);
		const id = u.bigint(1);
		const opaque = u.bytes(5);
		if (id !== undefined && opaque) (out.iceUpdates ??= []).push({ id, opaque });
	}
	const busy = d.bytes(5);
	if (busy) {
		const id = new Decoded(busy).bigint(1);
		if (id !== undefined) out.busy = { id };
	}
	const hangup = d.bytes(7);
	if (hangup) {
		const h = new Decoded(hangup);
		const id = h.bigint(1);
		if (id !== undefined) out.hangup = { id, type: h.uint(2) ?? 0, deviceId: h.uint(3) };
	}
	out.destinationDeviceId = d.uint(9);
	const opaque = d.bytes(10);
	if (opaque) {
		const o = new Decoded(opaque);
		out.opaque = { data: o.bytes(1), urgency: o.uint(2) };
	}
	return out;
}

// --- RingRTC signaling.proto ---

export const VIDEO_CODEC = { VP8: 8, VP9: 9 } as const;

export type ConnectionParametersV4 = {
	/** Raw X25519 public key, 32 bytes. */
	publicKey: Uint8Array;
	iceUfrag: string;
	icePwd: string;
	maxBitrateBps?: bigint;
	encodeVideoCodecs: number[];
	decodeVideoCodecs: number[];
};

function encodeV4(p: ConnectionParametersV4): Uint8Array {
	return encode([
		[1, p.publicKey],
		[2, p.iceUfrag],
		[3, p.icePwd],
		[5, p.maxBitrateBps],
		...p.encodeVideoCodecs.map((c): [number, Uint8Array] => [6, encode([[1, c]])]),
		...p.decodeVideoCodecs.map((c): [number, Uint8Array] => [7, encode([[1, c]])]),
	]);
}

function decodeV4(b: Uint8Array): ConnectionParametersV4 | undefined {
	const d = new Decoded(b);
	const publicKey = d.bytes(1);
	const iceUfrag = d.string(2);
	const icePwd = d.string(3);
	if (!publicKey || !iceUfrag || !icePwd) return undefined;
	const codecs = (n: number) =>
		(d.fields.get(n) ?? []).flatMap((v) => {
			const t = v instanceof Uint8Array ? new Decoded(v).uint(1) : undefined;
			return t === undefined ? [] : [t];
		});
	return { publicKey, iceUfrag, icePwd, maxBitrateBps: d.bigint(5), encodeVideoCodecs: codecs(6), decodeVideoCodecs: codecs(7) };
}

/** Offer and Answer are the same shape: { v4 = 4 }. */
export function encodeOfferOrAnswer(p: ConnectionParametersV4): Uint8Array {
	return encode([[4, encodeV4(p)]]);
}

export function decodeOfferOrAnswer(b: Uint8Array): ConnectionParametersV4 | undefined {
	try {
		const v4 = new Decoded(b).bytes(4);
		return v4 && decodeV4(v4);
	} catch {
		return undefined;
	}
}

/** IceCandidate { added_V3 = 2 { sdp = 1 } }. */
export function encodeIceCandidate(sdp: string): Uint8Array {
	return encode([[2, encode([[1, sdp]])]]);
}

/** The candidate's SDP; undefined for a removal or anything unreadable. */
export function decodeIceCandidate(b: Uint8Array): string | undefined {
	try {
		const added = new Decoded(b).bytes(2);
		return added && new Decoded(added).string(1);
	} catch {
		return undefined;
	}
}

// --- RingRTC rtp_data.proto ---

export type RtpDataMessage = {
	accepted?: { id: bigint };
	hangup?: { id: bigint; type: number; deviceId?: number };
	senderStatus?: { id: bigint; videoEnabled?: boolean; sharingScreen?: boolean; audioEnabled?: boolean };
	seqnum?: bigint;
};

export function encodeRtpData(m: RtpDataMessage): Uint8Array {
	return encode([
		[1, m.accepted && encode([[1, m.accepted.id]])],
		[2, m.hangup && encode([[1, m.hangup.id], [2, m.hangup.type], [3, m.hangup.deviceId]])],
		[3, m.senderStatus && encode([[1, m.senderStatus.id], [2, m.senderStatus.videoEnabled], [3, m.senderStatus.sharingScreen], [4, m.senderStatus.audioEnabled]])],
		[4, m.seqnum],
	]);
}

export function decodeRtpData(b: Uint8Array): RtpDataMessage | undefined {
	try {
		const d = new Decoded(b);
		const out: RtpDataMessage = { seqnum: d.bigint(4) };
		const accepted = d.bytes(1);
		const aid = accepted && new Decoded(accepted).bigint(1);
		if (aid !== undefined) out.accepted = { id: aid };
		const hangup = d.bytes(2);
		if (hangup) {
			const h = new Decoded(hangup);
			const id = h.bigint(1);
			if (id !== undefined) out.hangup = { id, type: h.uint(2) ?? 0, deviceId: h.uint(3) };
		}
		const status = d.bytes(3);
		if (status) {
			const s = new Decoded(status);
			const id = s.bigint(1);
			if (id !== undefined) out.senderStatus = { id, videoEnabled: s.bool(2), sharingScreen: s.bool(3), audioEnabled: s.bool(4) };
		}
		return out;
	} catch {
		return undefined;
	}
}

// --- SRTP keys ---

const KDF_INFO = enc.encode("Signal_Calling_20200807_SignallingDH_SRTPKey_KDF");

/**
 * ringrtc negotiate_srtp_keys: HKDF-SHA256 (32 zero bytes of salt) over X25519(ours, theirs), info =
 * label || caller identity key || callee identity key (both without the 0x05 type byte), split into
 * the offer's key and salt, then the answer's. The offerer sends with the offer key.
 */
export async function negotiateSrtpKeys(
	localPrivateKey: Uint8Array,
	remotePublicKey: Uint8Array,
	callerIdentityKey: Uint8Array,
	calleeIdentityKey: Uint8Array,
): Promise<{ offer: SrtpKey; answer: SrtpKey }> {
	if (remotePublicKey.length !== 32) throw new Error("call: the remote SRTP public key must be 32 bytes");
	const shared = await agree(localPrivateKey, concat(new Uint8Array([5]), remotePublicKey));
	if (shared.every((b) => b === 0)) throw new Error("call: non-contributory remote SRTP key");
	const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
	const info = concat(KDF_INFO, stripKeyType(callerIdentityKey), stripKeyType(calleeIdentityKey));
	const bytes = 2 * (SRTP_KEY_BYTES + SRTP_SALT_BYTES);
	const okm = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info }, ikm, bytes * 8));
	let off = 0;
	const take = (n: number) => okm.slice(off, (off += n));
	const offer = { key: take(SRTP_KEY_BYTES), salt: take(SRTP_SALT_BYTES) };
	const answer = { key: take(SRTP_KEY_BYTES), salt: take(SRTP_SALT_BYTES) };
	return { offer, answer };
}

/** An identity key as RingRTC takes it: the 32 key bytes, without libsignal's 0x05 type byte. */
export function stripKeyType(key: Uint8Array): Uint8Array {
	return key.length === 33 && key[0] === 5 ? key.subarray(1) : key;
}
