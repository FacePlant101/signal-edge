// One incoming envelope → decrypted, persisted protocol state → message records.
// Ported from Signal-Desktop ts/textsecure/MessageReceiver.preload.ts (innerDecrypt).

import { CIPHERTEXT, ENVELOPE, decodeEnvelope, distributionId, parseContent, unpad, type ParsedContent } from "./content.js";
import { preKeyMessageIdentity, type IdentityLog } from "./identities.js";
import { DecryptFailure } from "./retry.js";
import { unseal } from "./sealed.js";
import type { OurIdentity, ProtocolStore } from "./store.js";
import { signal } from "./wasm.js";

export type Self = { aci: string; pni?: string; deviceId: number };

export type ReceiveResult =
	| { status: "ignored"; reason: string }
	| { status: "decrypted"; sender: string; senderDevice: number; parsed: ParsedContent; serverGuid?: string; identityChanged?: boolean };

export async function receiveEnvelope(
	body: Uint8Array,
	self: Self,
	stores: Partial<Record<OurIdentity, ProtocolStore>>,
	identityPairs: Partial<Record<OurIdentity, Uint8Array>>,
	identities: IdentityLog,
): Promise<ReceiveResult> {
	const sig = signal();
	const env = decodeEnvelope(body);
	if (env.type === ENVELOPE.SERVER_DELIVERY_RECEIPT) return { status: "ignored", reason: "server delivery receipt" };
	if (env.story) return { status: "ignored", reason: "story" };
	if (!env.content) return { status: "ignored", reason: "no content" };

	// Messages to our phone-number identity (first contact from someone without our ACI) use the PNI keys.
	const ours: OurIdentity = env.destinationServiceId?.startsWith("PNI:") ? "pni" : "aci";
	const store = stores[ours];
	const identityPair = identityPairs[ours];
	if (!store || !identityPair) return { status: "ignored", reason: `no ${ours} identity` };
	const localName = ours === "aci" ? self.aci : `PNI:${self.pni}`;

	let sender: string;
	let device: number;
	let type: number;
	let ciphertext: Uint8Array;
	let sealedGroupId: Uint8Array | undefined;
	if (env.type === ENVELOPE.UNIDENTIFIED_SENDER) {
		const u = unseal(env.content, identityPair, env.serverTimestamp ?? Date.now(), self.aci, self.deviceId);
		sender = u.sender_aci;
		device = u.sender_device;
		type = u.msg_type;
		ciphertext = u.contents;
		sealedGroupId = u.group_id ?? undefined;
		u.free();
	} else {
		if (!env.sourceServiceId || !env.sourceDevice) return { status: "ignored", reason: "unsealed envelope without sender" };
		sender = env.sourceServiceId;
		device = env.sourceDevice;
		type = env.type === ENVELOPE.DOUBLE_RATCHET ? CIPHERTEXT.WHISPER : env.type === ENVELOPE.PREKEY_MESSAGE ? CIPHERTEXT.PREKEY : env.type === ENVELOPE.PLAINTEXT_CONTENT ? CIPHERTEXT.PLAINTEXT : -1;
		ciphertext = env.content;
	}
	if (ours === "pni" && type !== CIPHERTEXT.PREKEY) return { status: "ignored", reason: "non-PreKey message to PNI" };

	const remote = () => new sig.WasmProtocolAddress(sender, device);
	// Only libsignal's own decrypt failures ask the sender to resend (src/signal/retry.ts); anything after
	// a successful decrypt (padding, storage) would fail the same way on the resent copy.
	const decrypting = async <T>(fn: () => Promise<T>): Promise<T> => {
		try {
			return await fn();
		} catch (e) {
			throw new DecryptFailure({ sender, device, type, ciphertext, timestamp: env.clientTimestamp, ours, groupId: sealedGroupId }, e);
		}
	};
	let plaintext: Uint8Array;
	let identityChanged = false;
	if (type === CIPHERTEXT.WHISPER || type === CIPHERTEXT.PREKEY) {
		// A new session carries the sender's identity key: check it against our record first.
		const identityKey = type === CIPHERTEXT.PREKEY ? preKeyMessageIdentity(ciphertext) : undefined;
		const check = identityKey && (await identities.check(sender, identityKey));
		if (check === "changed") store.resetIdentityStore(); // else libsignal rejects the new key until restart
		const wasmType = type === CIPHERTEXT.PREKEY ? sig.message_type_pre_key() : sig.message_type_signal();
		const r = await decrypting(() => sig.decryptMessage(ciphertext, wasmType, remote(), new sig.WasmProtocolAddress(localName, self.deviceId), store.sessions, store.identityStore, store.preKeys, store.signedPreKeys, store.kyberPreKeys));
		plaintext = unpad(r.plaintext.slice());
		await store.afterDecrypt(sender, device, r);
		r.free();
		// Recorded only after the message decrypted with it.
		if (identityKey && check !== "same") await identities.save(sender, identityKey);
		identityChanged = check === "changed";
	} else if (type === CIPHERTEXT.SENDER_KEY) {
		const aci = stores.aci!;
		plaintext = unpad(await decrypting(() => sig.decryptGroupMessage(remote(), ciphertext, aci.senderKeys)));
		await aci.saveSenderKey(sender, device, distributionId(ciphertext, true));
	} else if (type === CIPHERTEXT.PLAINTEXT) {
		// PlaintextContent: a marker byte, then padded Content (only decryption-error receipts).
		plaintext = unpad(ciphertext.subarray(1));
	} else {
		return { status: "ignored", reason: `unknown message type ${type}` };
	}

	let parsed = parseContent(plaintext, sender, device, self.aci, sealedGroupId);
	// PlaintextContent isn't end-to-end authenticated: as Desktop, use only its DecryptionErrorMessage.
	if (type === CIPHERTEXT.PLAINTEXT) {
		parsed = { records: [], decryptionError: parsed.decryptionError, kinds: parsed.decryptionError ? ["decryption-error"] : ["plaintext:ignored"], groups: [] };
	}
	if (parsed.senderKeyDistribution) {
		const aci = stores.aci!;
		await sig.processSenderKeyDistribution(remote(), parsed.senderKeyDistribution, aci.senderKeys);
		await aci.saveSenderKey(sender, device, distributionId(parsed.senderKeyDistribution, false));
	}
	return { status: "decrypted", sender, senderDevice: device, parsed, serverGuid: env.serverGuid, identityChanged };
}
