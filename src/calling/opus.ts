// The built-in Opus codec: libopus (Xiph, v1.5.2), compiled to WASM by opus/ (src/vendor/signal-opus).

import * as opus from "../vendor/signal-opus/signal_opus.js";
import { wasmModule } from "../runtime.js";
import type { OpusCodec } from "./call.js";

let ready = false;

function lib(): typeof opus {
	if (!ready) {
		opus.initSync({ module: wasmModule("opus") });
		ready = true;
	}
	return opus;
}

export type OpusCodecOptions = {
	/** Encoder bitrate in bits per second, constant (default 32000, RingRTC's for 1:1 calls). */
	bitrate?: number;
	/** Frame length for sendPcm(): 10, 20, 40 or 60 ms (default 20; Signal's apps send 60). */
	frameMs?: 10 | 20 | 40 | 60;
};

/**
 * libopus at 48 kHz mono, set up as RingRTC sets up Opus for 1:1 calls (VoIP, constant bitrate,
 * in-band FEC, DTX). One per call: `callOptions: { codec: () => opusCodec() }`.
 */
export function opusCodec(opts: OpusCodecOptions = {}): OpusCodec {
	const frameMs = opts.frameMs ?? 20;
	if (![10, 20, 40, 60].includes(frameMs)) throw new Error("opusCodec: frameMs must be 10, 20, 40 or 60");
	const o = lib();
	const encoder = new o.OpusEncoder(opts.bitrate ?? 32_000);
	const decoder = new o.OpusDecoder();
	return {
		frameSize: 48 * frameMs,
		encode: (pcm) => encoder.encode(pcm),
		decode: (packet) => decoder.decode(packet),
		conceal: (samples, next) => decoder.conceal(samples, next),
		free() {
			encoder.free();
			decoder.free();
		},
	};
}
