/* tslint:disable */
/* eslint-disable */

/**
 * A 48 kHz mono decoder.
 */
export class OpusDecoder {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Concealment for `samples` of lost audio (a multiple of 2.5 ms); with `fec_packet` (the packet
     * after the gap) the loss is rebuilt from its in-band FEC data where it carries some.
     */
    conceal(samples: number, fec_packet?: Uint8Array | number[] | null): Int16Array;
    /**
     * One packet → its samples (stereo packets are mixed down to mono by libopus).
     */
    decode(packet: Uint8Array | number[]): Int16Array;
    constructor();
}

/**
 * A 48 kHz mono VoIP encoder, set up as RingRTC sets up Opus for 1:1 calls (CBR, in-band FEC, DTX).
 */
export class OpusEncoder {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * One frame (2.5, 5, 10, 20, 40 or 60 ms of 48 kHz mono samples) → one Opus packet.
     */
    encode(pcm: Int16Array | number[]): Uint8Array;
    /**
     * `bitrate` in bits per second (RingRTC: 32000 at most for 1:1 calls).
     */
    constructor(bitrate: number);
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_opusdecoder_free: (a: number, b: number) => void;
    readonly abort: () => void;
    readonly calloc: (a: number, b: number) => number;
    readonly free: (a: number) => void;
    readonly malloc: (a: number) => number;
    readonly __wbg_opusencoder_free: (a: number, b: number) => void;
    readonly opusdecoder_conceal: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly opusdecoder_decode: (a: number, b: number, c: number) => [number, number, number, number];
    readonly opusdecoder_new: () => [number, number, number];
    readonly opusencoder_encode: (a: number, b: number, c: number) => [number, number, number, number];
    readonly realloc: (a: number, b: number) => number;
    readonly opusencoder_new: (a: number) => [number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
