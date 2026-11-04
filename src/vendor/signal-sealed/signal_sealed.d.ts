/* tslint:disable */
/* eslint-disable */

export class GroupParams {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Group identifier (32 bytes), as used in `group:<base64>` chat ids.
     */
    get group_id(): Uint8Array;
    /**
     * Group identifier (32 bytes), as used in `group:<base64>` chat ids.
     */
    set group_id(value: Uint8Array | number[]);
    /**
     * Serialized GroupPublicParams: the username half of the groups-server Basic auth (hex).
     */
    get public_params(): Uint8Array;
    /**
     * Serialized GroupPublicParams: the username half of the groups-server Basic auth (hex).
     */
    set public_params(value: Uint8Array | number[]);
    /**
     * Serialized GroupSecretParams: keep secret, pass back to the functions below.
     */
    get secret_params(): Uint8Array;
    /**
     * Serialized GroupSecretParams: keep secret, pass back to the functions below.
     */
    set secret_params(value: Uint8Array | number[]);
}

export class Unsealed {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    content_hint: number;
    get contents(): Uint8Array;
    set contents(value: Uint8Array | number[]);
    get group_id(): Uint8Array | undefined;
    set group_id(value: Uint8Array | number[] | null | undefined);
    /**
     * CiphertextMessageType: 2 Whisper, 3 PreKey, 7 SenderKey, 8 Plaintext.
     */
    msg_type: number;
    sender_aci: string;
    sender_device: number;
    get sender_e164(): string | undefined;
    set sender_e164(value: string | null | undefined);
}

/**
 * Fresh presentation of `credential` for one group: the password half of the groups-server
 * Basic auth (hex).
 */
export function auth_presentation(server_public_params: Uint8Array | number[], group_secret_params: Uint8Array | number[], credential: Uint8Array | number[]): Uint8Array;

/**
 * Group attribute blobs (title, description, timer): returns the GroupAttributeBlob protobuf.
 */
export function decrypt_blob(group_secret_params: Uint8Array | number[], ciphertext: Uint8Array | number[]): Uint8Array;

/**
 * A member's profile key from group state (Member.profileKey, a ProfileKeyCiphertext), for `aci`.
 */
export function decrypt_profile_key(group_secret_params: Uint8Array | number[], ciphertext: Uint8Array | number[], aci: string): Uint8Array;

/**
 * Member user ids: returns the service id string (plain UUID for an ACI, `PNI:<uuid>` for a PNI).
 */
export function decrypt_service_id(group_secret_params: Uint8Array | number[], ciphertext: Uint8Array | number[]): string;

/**
 * Unidentified-access key for sealed-sender sends to the owner of `profile_key` (32 bytes).
 */
export function derive_access_key(profile_key: Uint8Array | number[]): Uint8Array;

export function group_params(master_key: Uint8Array | number[]): GroupParams;

/**
 * Master key (SVR key) from the account entropy pool, as Desktop `deriveMasterKey`.
 */
export function master_key_from_entropy_pool(pool: string): Uint8Array;

/**
 * One entry of `GET /v1/certificate/auth/group`: verifies the response for our ACI and PNI
 * and returns the serialized AuthCredentialWithPni for that redemption day.
 */
export function receive_auth_credential(server_public_params: Uint8Array | number[], aci: string, pni: string, redemption_time_secs: number, response: Uint8Array | number[]): Uint8Array;

/**
 * Seals `contents` (a CiphertextMessage of type `msg_type`: 2 Whisper, 3 PreKey, 7 SenderKey,
 * 8 Plaintext) for `destination_aci`.`destination_device`, whose identity key is
 * `destination_identity_key` (33 bytes), from us (`identity_key_pair`, libsignal serialization)
 * with our `sender_certificate` from `GET /v1/certificate/delivery`.
 */
export function seal(destination_aci: string, destination_device: number, destination_identity_key: Uint8Array | number[], identity_key_pair: Uint8Array | number[], sender_certificate: Uint8Array | number[], msg_type: number, contents: Uint8Array | number[], content_hint: number, group_id?: Uint8Array | number[] | null): Uint8Array;

/**
 * Expiry of a sender certificate, in epoch milliseconds (refetch before it passes).
 */
export function sender_certificate_expiration(sender_certificate: Uint8Array | number[]): number;

/**
 * A sender certificate chained to a test trust root (`trust_root_private`, 32 bytes) instead of Signal's.
 */
export function test_sender_certificate(trust_root_private: Uint8Array | number[], sender_aci: string, sender_device: number, sender_identity_public: Uint8Array | number[], expiration_ms: number): Uint8Array;

/**
 * Removes the sealed-sender layer addressed to `identity_key_pair` (libsignal IdentityKeyPair
 * serialization). Rejects certificates not signed via Signal's trust roots, expired at
 * `timestamp_ms`, or sent by this very device.
 */
export function unseal(ciphertext: Uint8Array | number[], identity_key_pair: Uint8Array | number[], timestamp_ms: number, local_aci: string, local_device: number): Unsealed;

/**
 * `unseal`, but validating against a test trust root (`trust_root_public`, 33 bytes).
 */
export function unseal_for_test(ciphertext: Uint8Array | number[], identity_key_pair: Uint8Array | number[], timestamp_ms: number, local_aci: string, local_device: number, trust_root_public: Uint8Array | number[]): Unsealed;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_get_groupparams_group_id: (a: number) => [number, number];
    readonly __wbg_get_groupparams_public_params: (a: number) => [number, number];
    readonly __wbg_get_groupparams_secret_params: (a: number) => [number, number];
    readonly __wbg_get_unsealed_content_hint: (a: number) => number;
    readonly __wbg_get_unsealed_contents: (a: number) => [number, number];
    readonly __wbg_get_unsealed_group_id: (a: number) => [number, number];
    readonly __wbg_get_unsealed_msg_type: (a: number) => number;
    readonly __wbg_get_unsealed_sender_aci: (a: number) => [number, number];
    readonly __wbg_get_unsealed_sender_device: (a: number) => number;
    readonly __wbg_get_unsealed_sender_e164: (a: number) => [number, number];
    readonly __wbg_groupparams_free: (a: number, b: number) => void;
    readonly __wbg_set_groupparams_group_id: (a: number, b: number, c: number) => void;
    readonly __wbg_set_groupparams_public_params: (a: number, b: number, c: number) => void;
    readonly __wbg_set_groupparams_secret_params: (a: number, b: number, c: number) => void;
    readonly __wbg_set_unsealed_content_hint: (a: number, b: number) => void;
    readonly __wbg_set_unsealed_contents: (a: number, b: number, c: number) => void;
    readonly __wbg_set_unsealed_group_id: (a: number, b: number, c: number) => void;
    readonly __wbg_set_unsealed_msg_type: (a: number, b: number) => void;
    readonly __wbg_set_unsealed_sender_aci: (a: number, b: number, c: number) => void;
    readonly __wbg_set_unsealed_sender_device: (a: number, b: number) => void;
    readonly __wbg_set_unsealed_sender_e164: (a: number, b: number, c: number) => void;
    readonly __wbg_unsealed_free: (a: number, b: number) => void;
    readonly auth_presentation: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly decrypt_blob: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decrypt_profile_key: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly decrypt_service_id: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly derive_access_key: (a: number, b: number) => [number, number, number, number];
    readonly group_params: (a: number, b: number) => [number, number, number];
    readonly master_key_from_entropy_pool: (a: number, b: number) => [number, number, number, number];
    readonly receive_auth_credential: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly seal: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number, number, number];
    readonly sender_certificate_expiration: (a: number, b: number) => [number, number, number];
    readonly test_sender_certificate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly unseal: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly unseal_for_test: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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
