/* tslint:disable */
/* eslint-disable */

export class TlsClient {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Queues a close_notify alert. Call `outgoing()` afterwards.
     */
    close(): void;
    /**
     * Starts a TLS 1.3 handshake to `server_name`. Call `outgoing()` to get the ClientHello.
     */
    constructor(server_name: string);
    /**
     * Bytes to write to the socket (handshake records, ciphertext, alerts).
     */
    outgoing(): Uint8Array;
    /**
     * Feeds bytes read from the socket. Returns any application plaintext they decrypted to.
     * On error, still call `outgoing()` and send it: it may hold a TLS alert for the peer.
     */
    receive(data: Uint8Array | number[]): Uint8Array;
    /**
     * Queues as much application plaintext as rustls will buffer (64 KiB by default) and
     * returns how many bytes it took. Call `outgoing()`, send that, then pass the rest.
     */
    send(data: Uint8Array | number[]): number;
    readonly handshaking: boolean;
    /**
     * True once the peer sent close_notify.
     */
    readonly peer_closed: boolean;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_tlsclient_free: (a: number, b: number) => void;
    readonly tlsclient_close: (a: number) => void;
    readonly tlsclient_handshaking: (a: number) => number;
    readonly tlsclient_new: (a: number, b: number) => [number, number, number];
    readonly tlsclient_outgoing: (a: number) => [number, number, number, number];
    readonly tlsclient_peer_closed: (a: number) => number;
    readonly tlsclient_receive: (a: number, b: number, c: number) => [number, number, number, number];
    readonly tlsclient_send: (a: number, b: number, c: number) => [number, number, number];
    readonly ring_core_0_17_14__bn_mul_mont: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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
