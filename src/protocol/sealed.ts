import * as extra from "../vendor/signal-sealed/signal_sealed.js";
import type { Unsealed } from "../vendor/signal-sealed/signal_sealed.js";
import { wasmModule } from "../runtime.js";

let ready = false;

/** Our own libsignal build (sealed/): sealed sender and zkgroup, initialized on first use. */
export function libsignalExtra(): typeof extra {
	if (!ready) {
		extra.initSync({ module: wasmModule("sealed") });
		ready = true;
	}
	return extra;
}

/** Sealed-sender content hints (libsignal ContentHint): can the recipient ask for it again? */
export const CONTENT_HINT = { DEFAULT: 0, RESENDABLE: 1, IMPLICIT: 2 } as const;

/** Unidentified-access key from a profile key (zkgroup ProfileKey::derive_access_key). */
export function accessKey(profileKey: Uint8Array): Uint8Array {
	return libsignalExtra().derive_access_key(profileKey);
}

/** Removes the sealed-sender layer (sealed/src/lib.rs); throws on an invalid sender certificate. */
export function unseal(ciphertext: Uint8Array, identityKeyPair: Uint8Array, validAt: number, localAci: string, localDevice: number): Unsealed {
	return libsignalExtra().unseal(ciphertext, identityKeyPair, validAt, localAci, localDevice);
}
