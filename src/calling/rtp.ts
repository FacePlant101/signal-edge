// RTP packets (RFC 3550) as RingRTC's 1:1 calls use them: Opus audio and the RTP data channel.

import { readU16, readU32 } from "./stun.js";
import { rtpHeaderLength } from "./srtp.js";

/** RingRTC rffi/src/constants.h and core/connection.rs. */
export const OPUS_PT = 102;
export const RTP_DATA_PT = 101;
export const RTP_DATA_SSRC = 0xd;
/** Opus's RTP clock (RFC 7587): 48 kHz whatever the audio bandwidth. */
export const OPUS_CLOCK = 48_000;

/** Our audio SSRC: RingRTC gives the caller 1002 and the callee 2002 (Rust_sessionDescriptionFromV4). */
export function audioSsrc(caller: boolean): number {
	return caller ? 1002 : 2002;
}

export type RtpPacket = { pt: number; seq: number; timestamp: number; ssrc: number; marker: boolean; payload: Uint8Array };

export function buildRtp(p: RtpPacket): Uint8Array {
	const out = new Uint8Array(12 + p.payload.length);
	const dv = new DataView(out.buffer);
	out[0] = 0x80;
	out[1] = (p.marker ? 0x80 : 0) | (p.pt & 0x7f);
	dv.setUint16(2, p.seq & 0xffff);
	dv.setUint32(4, p.timestamp >>> 0);
	dv.setUint32(8, p.ssrc >>> 0);
	out.set(p.payload, 12);
	return out;
}

export function parseRtp(b: Uint8Array): RtpPacket | undefined {
	const h = rtpHeaderLength(b);
	if (h === undefined) return undefined;
	let end = b.length;
	if (b[0]! & 0x20) {
		const pad = b[b.length - 1]!;
		if (!pad || h + pad > b.length) return undefined;
		end -= pad;
	}
	return { pt: b[1]! & 0x7f, marker: !!(b[1]! & 0x80), seq: readU16(b, 2), timestamp: readU32(b, 4), ssrc: readU32(b, 8), payload: b.subarray(h, end) };
}

/** RTCP shares the port (rtcp-mux, RFC 5761): payload types 192–223 in the second byte. */
export function isRtcp(b: Uint8Array): boolean {
	return b.length >= 8 && b[0]! >> 6 === 2 && b[1]! >= 192 && b[1]! <= 223;
}

/** True for RTP or RTCP (version 2); STUN starts with two zero bits instead. */
export function isRtpOrRtcp(b: Uint8Array): boolean {
	return b.length >= 12 && b[0]! >> 6 === 2;
}

/** Samples (at 48 kHz) in an Opus packet, from its TOC byte (RFC 6716 §3.1); 0 if malformed. */
export function opusSamples(packet: Uint8Array): number {
	if (!packet.length) return 0;
	const toc = packet[0]!;
	const config = toc >> 3;
	let frameTenthsMs: number;
	if (config < 12) frameTenthsMs = [100, 200, 400, 600][config & 3]!;
	else if (config < 16) frameTenthsMs = [100, 200][config & 1]!;
	else frameTenthsMs = [25, 50, 100, 200][config & 3]!;
	const code = toc & 3;
	let frames: number;
	if (code === 0) frames = 1;
	else if (code !== 3) frames = 2;
	else {
		if (packet.length < 2) return 0;
		frames = packet[1]! & 0x3f;
	}
	const samples = (frames * frameTenthsMs * OPUS_CLOCK) / 10_000;
	// RFC 6716: at most 120 ms per packet.
	return samples > OPUS_CLOCK * 0.12 ? 0 : samples;
}
