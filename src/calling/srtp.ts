// SRTP with AEAD_AES_256_GCM (RFC 7714), the only suite RingRTC negotiates for 1:1 calls (keys from
// the signaled X25519 exchange, no DTLS). RTP only: RTCP isn't needed to send or play audio, and
// incoming RTCP is dropped unread. Test vectors: RFC 7714 §16, RFC 6188 (key derivation).

import { concat } from "../util/bytes.js";
import { readU16, readU32 } from "./stun.js";

export const SRTP_KEY_BYTES = 32;
export const SRTP_SALT_BYTES = 12;
const TAG_BYTES = 16;
const REPLAY_WINDOW = 128;

/** A master key and salt, as negotiated. */
export type SrtpKey = { key: Uint8Array; salt: Uint8Array };

const LABEL_RTP_ENCRYPTION = 0x00;
const LABEL_RTP_SALT = 0x02;

/** RFC 3711 §4.3 key derivation with the AES-CM PRF (key derivation rate 0). */
export async function deriveSessionKey(master: SrtpKey, label: number, bytes: number): Promise<Uint8Array> {
	const block = new Uint8Array(16);
	block.set(master.salt.subarray(0, 14));
	block[7]! ^= label;
	const key = await crypto.subtle.importKey("raw", master.key, "AES-CTR", false, ["encrypt"]);
	const out = await crypto.subtle.encrypt({ name: "AES-CTR", counter: block, length: 16 }, key, new Uint8Array(Math.ceil(bytes / 16) * 16));
	return new Uint8Array(out).subarray(0, bytes);
}

/** Length of an RTP header including CSRCs and the extension; undefined if malformed. */
export function rtpHeaderLength(p: Uint8Array): number | undefined {
	if (p.length < 12 || p[0]! >> 6 !== 2) return undefined;
	let len = 12 + 4 * (p[0]! & 0x0f);
	if (p[0]! & 0x10) {
		if (p.length < len + 4) return undefined;
		len += 4 + 4 * readU16(p, len + 2);
	}
	return len <= p.length ? len : undefined;
}

type ReceiveState = { roc: number; highest: number; window: bigint };

/** One direction of an SRTP session: protects what we send, or unprotects what we receive. */
export class SrtpSession {
	#key: CryptoKey;
	#salt: Uint8Array;
	/** Sending: rollover counter and last sequence number per SSRC. */
	#send = new Map<number, { roc: number; last: number }>();
	#receive = new Map<number, ReceiveState>();

	private constructor(key: CryptoKey, salt: Uint8Array) {
		this.#key = key;
		this.#salt = salt;
	}

	static async create(master: SrtpKey): Promise<SrtpSession> {
		if (master.key.length !== SRTP_KEY_BYTES || master.salt.length !== SRTP_SALT_BYTES) throw new Error("srtp: AES-256-GCM needs a 32-byte key and 12-byte salt");
		const sessionKey = await deriveSessionKey(master, LABEL_RTP_ENCRYPTION, SRTP_KEY_BYTES);
		const sessionSalt = await deriveSessionKey(master, LABEL_RTP_SALT, SRTP_SALT_BYTES);
		return SrtpSession.withSessionKeys(sessionKey, sessionSalt);
	}

	/** With already-derived session keys (the RFC 7714 vectors give these). */
	static async withSessionKeys(sessionKey: Uint8Array, sessionSalt: Uint8Array): Promise<SrtpSession> {
		const key = await crypto.subtle.importKey("raw", sessionKey, "AES-GCM", false, ["encrypt", "decrypt"]);
		return new SrtpSession(key, sessionSalt.slice());
	}

	#iv(ssrc: number, roc: number, seq: number): Uint8Array {
		const iv = new Uint8Array(12);
		const dv = new DataView(iv.buffer);
		dv.setUint32(2, ssrc);
		dv.setUint32(6, roc);
		dv.setUint16(10, seq);
		for (let i = 0; i < 12; i++) iv[i]! ^= this.#salt[i]!;
		return iv;
	}

	/** Encrypts an RTP packet. Sequence numbers must increase (wrapping); the ROC follows them. */
	async protect(packet: Uint8Array): Promise<Uint8Array> {
		const h = rtpHeaderLength(packet);
		if (h === undefined) throw new Error("srtp: malformed RTP packet");
		const ssrc = readU32(packet, 8);
		const seq = readU16(packet, 2);
		let s = this.#send.get(ssrc);
		if (!s) this.#send.set(ssrc, (s = { roc: 0, last: seq }));
		else {
			if (seq < s.last && s.last - seq > 0x8000) s.roc = (s.roc + 1) >>> 0;
			s.last = seq;
		}
		const header = packet.subarray(0, h);
		const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: this.#iv(ssrc, s.roc, seq), additionalData: header, tagLength: 128 }, this.#key, packet.subarray(h));
		return concat(header, new Uint8Array(ct));
	}

	/** Decrypts an SRTP packet; undefined if it doesn't authenticate or is a replay. */
	async unprotect(packet: Uint8Array): Promise<Uint8Array | undefined> {
		const h = rtpHeaderLength(packet);
		if (h === undefined || packet.length < h + TAG_BYTES) return undefined;
		const ssrc = readU32(packet, 8);
		const seq = readU16(packet, 2);
		const state = this.#receive.get(ssrc);
		// RFC 3711 Appendix A: the ROC the sender most likely used.
		let roc = state?.roc ?? 0;
		if (state) {
			if (state.highest < 0x8000) {
				if (seq - state.highest > 0x8000) roc = (state.roc - 1) >>> 0;
			} else if (state.highest - 0x8000 > seq) roc = (state.roc + 1) >>> 0;
		}
		const index = roc * 0x10000 + seq;
		if (state) {
			const highestIndex = state.roc * 0x10000 + state.highest;
			const behind = highestIndex - index;
			if (behind >= REPLAY_WINDOW) return undefined;
			if (behind >= 0 && (state.window >> BigInt(behind)) & 1n) return undefined;
		}
		let pt: ArrayBuffer;
		try {
			pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: this.#iv(ssrc, roc, seq), additionalData: packet.subarray(0, h), tagLength: 128 }, this.#key, packet.subarray(h));
		} catch {
			return undefined;
		}
		// Recorded only once authenticated, so forged packets can't move the window.
		const now = this.#receive.get(ssrc);
		if (!now) this.#receive.set(ssrc, { roc, highest: seq, window: 1n });
		else {
			const highestIndex = now.roc * 0x10000 + now.highest;
			const diff = index - highestIndex;
			const mask = (1n << BigInt(REPLAY_WINDOW)) - 1n;
			if (diff > 0) {
				now.window = ((now.window << BigInt(Math.min(diff, REPLAY_WINDOW))) | 1n) & mask;
				now.roc = roc;
				now.highest = seq;
			} else {
				if (-diff >= REPLAY_WINDOW || (now.window >> BigInt(-diff)) & 1n) return undefined; // raced a duplicate
				now.window |= 1n << BigInt(-diff);
			}
		}
		return concat(packet.subarray(0, h), new Uint8Array(pt));
	}
}
