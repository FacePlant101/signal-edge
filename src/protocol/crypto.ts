// Linking crypto that libsignal-wasm doesn't expose, done with WebCrypto.
// Ported from Signal-Desktop ts/textsecure/ProvisioningCipher.node.ts and ts/Crypto.node.ts.

import { concat, enc } from "../util/bytes.js";
import { decodeProvisionEnvelope, decodeProvisionMessage, encodeDeviceName, type ProvisionMessage } from "./proto.js";
import { signal } from "./wasm.js";

const subtle = crypto.subtle;
// PKCS#8 wrapper for a raw 32-byte X25519 private key (RFC 8410).
const X25519_PKCS8_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
const DJB_TYPE = 0x05;

/** X25519 between a libsignal private key (32 raw bytes) and public key (0x05 || 32 bytes). */
export async function agree(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
	if (privateKey.length !== 32) throw new Error("agree: private key must be 32 bytes");
	if (publicKey.length !== 33 || publicKey[0] !== DJB_TYPE) throw new Error("agree: expected 33-byte DJB public key");
	const priv = await subtle.importKey("pkcs8", concat(X25519_PKCS8_PREFIX, privateKey), { name: "X25519" }, false, ["deriveBits"]);
	const pub = await subtle.importKey("raw", publicKey.subarray(1), { name: "X25519" }, false, []);
	// The runtime takes the standard `public` member; workers-types names it `$public`.
	const params = { name: "X25519", public: pub } as unknown as SubtleCryptoDeriveKeyAlgorithm;
	return new Uint8Array(await subtle.deriveBits(params, priv, 256));
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return new Uint8Array(await subtle.sign("HMAC", k, data));
}

async function hkdf(input: Uint8Array, salt: Uint8Array, info: Uint8Array, bytes: number): Promise<Uint8Array> {
	const k = await subtle.importKey("raw", input, "HKDF", false, ["deriveBits"]);
	return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, bytes * 8));
}

/** Ephemeral key pair whose public half goes in the QR code. */
export function newProvisioningKeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
	const priv = signal().WasmPrivateKey.generate();
	return { privateKey: priv.serialize(), publicKey: priv.getPublicKey().serialize() };
}

/**
 * Decrypts the ProvisionEnvelope the primary device sends after scanning the QR code.
 * body = version(1) || iv(16) || AES-256-CBC ciphertext || HMAC-SHA256(32), keys from
 * HKDF(ECDH, salt = 32 zero bytes, info = "TextSecure Provisioning Message").
 */
export async function decryptProvisionEnvelope(envelopeBytes: Uint8Array, ourPrivateKey: Uint8Array): Promise<ProvisionMessage> {
	const { publicKey, body } = decodeProvisionEnvelope(envelopeBytes);
	if (!publicKey || !body) throw new Error("ProvisionEnvelope: missing publicKey or body");
	if (body[0] !== 1) throw new Error("ProvisionEnvelope: bad version");
	if (body.length < 1 + 16 + 16 + 32) throw new Error("ProvisionEnvelope: too short");

	const iv = body.subarray(1, 17);
	const ciphertext = body.subarray(17, body.length - 32);
	const mac = body.subarray(body.length - 32);

	const shared = await agree(ourPrivateKey, publicKey);
	const keys = await hkdf(shared, new Uint8Array(32), enc.encode("TextSecure Provisioning Message"), 64);
	const macKey = await subtle.importKey("raw", keys.subarray(32, 64), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
	if (!(await subtle.verify("HMAC", macKey, mac, body.subarray(0, body.length - 32)))) {
		throw new Error("ProvisionEnvelope: bad MAC");
	}
	const aesKey = await subtle.importKey("raw", keys.subarray(0, 32), "AES-CBC", false, ["decrypt"]);
	const plaintext = new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv }, aesKey, ciphertext));
	return decodeProvisionMessage(plaintext);
}

/**
 * Encrypts the device name to our ACI identity key, as Signal-Desktop's encryptDeviceName:
 * synthetic IV = HMAC(HMAC(ecdh, "auth"), name)[0..16], key = HMAC(HMAC(ecdh, "cipher"), iv),
 * AES-256-CTR with a zero counter. Returns the encoded DeviceName protobuf.
 */
export async function encryptDeviceName(name: string, identityPublicKey: Uint8Array): Promise<Uint8Array> {
	const plaintext = enc.encode(name);
	const eph = newProvisioningKeyPair();
	const master = await agree(eph.privateKey, identityPublicKey);

	const key1 = await hmacSha256(master, enc.encode("auth"));
	const syntheticIv = (await hmacSha256(key1, plaintext)).slice(0, 16);
	const key2 = await hmacSha256(master, enc.encode("cipher"));
	const cipherKey = await hmacSha256(key2, syntheticIv);

	const k = await subtle.importKey("raw", cipherKey, "AES-CTR", false, ["encrypt"]);
	const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-CTR", counter: new Uint8Array(16), length: 64 }, k, plaintext));
	return encodeDeviceName({ ephemeralPublic: eph.publicKey, syntheticIv, ciphertext });
}

/** Inverse of encryptDeviceName; used to self-test the port. */
export async function decryptDeviceName(
	d: { ephemeralPublic: Uint8Array; syntheticIv: Uint8Array; ciphertext: Uint8Array },
	identityPrivateKey: Uint8Array,
): Promise<string> {
	const master = await agree(identityPrivateKey, d.ephemeralPublic);
	const key2 = await hmacSha256(master, enc.encode("cipher"));
	const cipherKey = await hmacSha256(key2, d.syntheticIv);
	const k = await subtle.importKey("raw", cipherKey, "AES-CTR", false, ["decrypt"]);
	const plaintext = new Uint8Array(await subtle.decrypt({ name: "AES-CTR", counter: new Uint8Array(16), length: 64 }, k, d.ciphertext));
	const key1 = await hmacSha256(master, enc.encode("auth"));
	const iv = (await hmacSha256(key1, plaintext)).slice(0, 16);
	if (iv.some((b, i) => b !== d.syntheticIv[i])) throw new Error("DeviceName: synthetic IV mismatch");
	return new TextDecoder().decode(plaintext);
}
