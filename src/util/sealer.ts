import { enc, fromBase64, randomBytes } from "./bytes.js";

/**
 * AES-256-GCM for data at rest. The `aad` label binds each blob to where it is
 * stored (table and key), so a blob copied into another row fails to open.
 * Layout: iv(12) || ciphertext+tag.
 */
export class Sealer {
	private constructor(private readonly key: CryptoKey) {}

	static async fromBase64(b64: string | undefined): Promise<Sealer> {
		const raw = b64 ? fromBase64(b64) : undefined;
		if (raw?.length !== 32) throw new Error("storage key must be 32 bytes, base64");
		return new Sealer(await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]));
	}

	async seal(aad: string, data: Uint8Array): Promise<Uint8Array> {
		const iv = randomBytes(12);
		const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) }, this.key, data));
		const out = new Uint8Array(12 + ct.length);
		out.set(iv);
		out.set(ct, 12);
		return out;
	}

	async open(aad: string, blob: Uint8Array): Promise<Uint8Array> {
		return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: enc.encode(aad) }, this.key, blob.subarray(12)));
	}
}
