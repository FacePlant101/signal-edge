// Self-checks for the WebCrypto ports in crypto.ts. GET /test/link-crypto runs them.

import { concat, enc } from "../util/bytes.js";
import { agree, decryptDeviceName, decryptProvisionEnvelope, encryptDeviceName, newProvisioningKeyPair } from "../protocol/crypto.js";
import { Decoded, encode } from "../protocol/proto.js";

const hex = (s: string) => new Uint8Array(s.match(/../g)!.map((h) => parseInt(h, 16)));
const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

/** Builds a ProvisionEnvelope the way the primary device does (Signal-Android ProvisioningCipher.encrypt). */
async function sealProvisionMessage(plaintext: Uint8Array, recipientPublic: Uint8Array): Promise<Uint8Array> {
	const eph = newProvisioningKeyPair();
	const shared = await agree(eph.privateKey, recipientPublic);
	const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
	const keys = new Uint8Array(
		await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode("TextSecure Provisioning Message") }, ikm, 512),
	);
	const iv = crypto.getRandomValues(new Uint8Array(16));
	const aes = await crypto.subtle.importKey("raw", keys.subarray(0, 32), "AES-CBC", false, ["encrypt"]);
	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aes, plaintext));
	const signed = concat(new Uint8Array([1]), iv, ct);
	const macKey = await crypto.subtle.importKey("raw", keys.subarray(32, 64), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, signed));
	return encode([[1, eph.publicKey], [2, concat(signed, mac)]]);
}

export async function linkCryptoSelfTest() {
	// RFC 7748 section 6.1: Alice's private key with Bob's public key.
	const alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
	const bobPub = concat(new Uint8Array([5]), hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
	const x25519 = toHex(await agree(alicePriv, bobPub)) === "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

	// Device name: encrypt to an identity key, decrypt with its private half.
	const id = newProvisioningKeyPair();
	const encName = new Decoded(await encryptDeviceName("Claude (test)", id.publicKey));
	const deviceName = (await decryptDeviceName({ ephemeralPublic: encName.bytes(1)!, syntheticIv: encName.bytes(2)!, ciphertext: encName.bytes(3)! }, id.privateKey)) === "Claude (test)";

	// Provisioning envelope: seal as the phone would, then open with our key.
	const ours = newProvisioningKeyPair();
	const message = encode([[3, "+15550100"], [4, "123456"], [8, "00000000-0000-4000-8000-000000000001"]]);
	const opened = await decryptProvisionEnvelope(await sealProvisionMessage(message, ours.publicKey), ours.privateKey);
	const provisioning = opened.number === "+15550100" && opened.provisioningCode === "123456" && opened.aci === "00000000-0000-4000-8000-000000000001";

	// A tampered envelope must fail the MAC check.
	const sealed = await sealProvisionMessage(message, ours.publicKey);
	sealed[sealed.length - 40]! ^= 1;
	let tamperRejected = false;
	try {
		await decryptProvisionEnvelope(sealed, ours.privateKey);
	} catch (e) {
		tamperRejected = String(e).includes("bad MAC");
	}

	return { ok: x25519 && deviceName && provisioning && tamperRejected, x25519, deviceName, provisioning, tamperRejected };
}
