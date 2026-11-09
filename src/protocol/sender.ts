// 1:1 sending: per-device encryption with our persisted sessions, PUT /v1/messages,
// and the 409/410 device-list repair loop. Ported from Signal-Desktop
// ts/textsecure/OutgoingMessage.preload.ts and SendMessage.preload.ts.
// Sends to others are sealed sender when we have their access key (from their profile key) and
// identity key: the server delivers them without learning who sent them. Otherwise, and on a
// 401/403 for the access key, they are authenticated, as Desktop fails over.
// Every successful send is kept in the send log (if the context has one) so a contact whose
// device couldn't decrypt it can ask for it again (src/signal/retry.ts).

import { signalFetch } from "../net/http.js";
import { dec, fromBase64, randomBytes, toBase64 } from "../util/bytes.js";
import { encode } from "./proto.js";
import { CHAT_HOST } from "./socket.js";
import type { IdentityLog } from "./identities.js";
import type { SendLog } from "./retry.js";
import type { Expiry } from "./timers.js";
import { libsignalExtra } from "./sealed.js";
import type { ProtocolStore } from "./store.js";
import type { Mention } from "./content.js";
import { signal } from "./wasm.js";

const ENVELOPE_DOUBLE_RATCHET = 1;
const ENVELOPE_PREKEY_MESSAGE = 3;
const ENVELOPE_UNIDENTIFIED_SENDER = 6;
const ENVELOPE_PLAINTEXT_CONTENT = 8;
/** libsignal CiphertextMessageType::Plaintext, the inner type of a sealed PlaintextContent. */
const CIPHERTEXT_PLAINTEXT = 8;
const MAX_ATTEMPTS = 4;

/** Signal-Desktop padMessage: content, 0x80, zeros, to ceil((n+2)/80)*80 - 1 bytes. */
export function padMessage(content: Uint8Array): Uint8Array {
	const len = Math.ceil((content.length + 2) / 80) * 80 - 1;
	const out = new Uint8Array(len);
	out.set(content);
	out[content.length] = 0x80;
	return out;
}

/** Signal-Desktop getRandomPadding: 1-512 random bytes for SyncMessage.padding. */
export function randomPadding(): Uint8Array {
	const n = (new Uint16Array(randomBytes(2).buffer)[0]! & 0x1ff) + 1;
	return randomBytes(n);
}

/** DataMessage.Quote: id 1 (the quoted message's sentAt), authorAci 5, text 3, bodyRanges 6. */
export function quoteMessage(id: number, authorAci: string, text?: string, mentions: Mention[] = []): Uint8Array {
	return encode([[1, id], [5, authorAci], [3, text], ...mentions.map((m): [number, Uint8Array] => [6, bodyRange(m)])]);
}

/** BodyRange for a mention: start 1, length 2, mentionAci 3 (UTF-16 code units, as Signal's apps count). */
export function bodyRange(m: Mention): Uint8Array {
	return encode([[1, m.start], [2, m.length], [3, m.aci]]);
}

/** DataMessage.Reaction: emoji 1, remove 2, targetAuthorAci 4, targetSentTimestamp 5. */
export function reactionMessage(emoji: string, targetAuthorAci: string, targetSentAt: number, remove = false): Uint8Array {
	return encode([[1, emoji], [2, remove || undefined], [4, targetAuthorAci], [5, targetSentAt]]);
}

/** DataMessage { body, attachments[], expireTimer, profileKey, timestamp, groupV2 { masterKey, revision }, expireTimerVersion }. */
export function dataMessage(
	body: string | undefined,
	timestamp: number,
	profileKey?: Uint8Array,
	group?: { masterKey: Uint8Array; revision: number },
	attachments: Uint8Array[] = [],
	expiry: Expiry = {},
	extras: { quote?: Uint8Array; reaction?: Uint8Array; mentions?: Mention[] } = {},
): Uint8Array {
	const groupV2 = group && encode([[1, group.masterKey], [2, group.revision]]);
	return encode([
		[1, body || undefined],
		...attachments.map((p): [number, Uint8Array] => [2, p]),
		[5, expiry.expireTimer || undefined],
		[6, profileKey],
		[7, timestamp],
		[8, extras.quote],
		[15, groupV2],
		[16, extras.reaction],
		...(extras.mentions ?? []).map((m): [number, Uint8Array] => [18, bodyRange(m)]),
		[23, expiry.version], // 0 is written: "don't change the timer"
	]);
}

export function contentWithData(data: Uint8Array): Uint8Array {
	return encode([[1, data]]);
}

/**
 * Content { syncMessage { sent { destinationServiceId, timestamp, message, unidentifiedStatus[] }, padding } }.
 * Group messages have no destination and one status per member it was delivered to;
 * `unidentified` marks the ones reached by sealed sender (`sealedTo`).
 */
export function contentWithSentTranscript(destination: string | undefined, timestamp: number, data: Uint8Array, deliveredTo: string[], sealedTo: string[] = []): Uint8Array {
	const statuses = deliveredTo.map((id): [number, Uint8Array] => [5, encode([[3, id], [2, sealedTo.includes(id)]])]);
	const sent = encode([[7, destination], [2, timestamp], [3, data], ...statuses]);
	return encode([[2, encode([[1, sent], [8, randomPadding()]])]]);
}

type DeviceKeys = {
	deviceId: number;
	registrationId: number;
	preKey?: { keyId: number; publicKey: string } | null;
	signedPreKey?: { keyId: number; publicKey: string; signature: string } | null;
	pqPreKey?: { keyId: number; publicKey: string; signature: string } | null;
};
type KeysResponse = { identityKey: string; devices: DeviceKeys[] };

export type SendContext = {
	ourAci: string;
	ourDeviceId: number;
	auth: string;
	store: ProtocolStore;
	identities: IdentityLog;
	/** Service ids whose identity key changed while sending (filled in by sendToServiceId). */
	identityChanges?: string[];
	/** Where sent Content is kept for resending; leave out for messages that must not be kept. */
	sendLog?: SendLog;
	/** Our sender certificate and identity key pair, for sealed-sender sends. */
	sealedSender?: { certificate: Uint8Array; identityKeyPair: Uint8Array };
	/** Service ids a send reached sealed (filled in by sendToServiceId). */
	sealedTo?: string[];
	/** Called when the server refuses an access key with 401/403 (the send then goes authenticated). */
	onAccessKeyRefused?: (serviceId: string, accessKey: Uint8Array) => void;
	/** Why a send to someone else went authenticated (for counters); not called for sends to ourselves. */
	onUnsealed?: (serviceId: string, reason: "no access key" | "no certificate" | "no identity key") => void;
	/** Aborts the send's requests (SignalClient.reset() uses it so a forgotten account's send stops). */
	signal?: AbortSignal;
};

export type SendOptions = {
	/** `content` is a serialized PlaintextContent, sent unencrypted (retry requests only). */
	plaintext?: boolean;
	urgent?: boolean;
	/** The recipient's unidentified-access key: send sealed sender (needs ctx.sealedSender). */
	accessKey?: Uint8Array;
	/** libsignal ContentHint for the sealed layer (CONTENT_HINT in sealed.ts). */
	contentHint?: number;
	/** Group id, carried in the sealed layer of group messages. */
	groupId?: Uint8Array;
};

/**
 * GET /v2/keys/{serviceId}/{device} and builds a session per device returned (not our own device),
 * checking and recording the identity key. With an access key the fetch is unidentified (as Desktop),
 * so the server can't tie us to the recipient; "refused" means it was refused and the fetch was done
 * with our credentials instead.
 */
export async function fetchKeys(ctx: SendContext, serviceId: string, device: number | "*", accessKey?: Uint8Array): Promise<"refused" | undefined> {
	const sig = signal();
	const { store } = ctx;
	const isSelf = serviceId === ctx.ourAci;
	const addr = (d: number) => new sig.WasmProtocolAddress(serviceId, d);
	const local = () => new sig.WasmProtocolAddress(ctx.ourAci, ctx.ourDeviceId);
	const path = `/v2/keys/${serviceId}/${device}`;
	let refused: "refused" | undefined;
	let res = accessKey ? await signalFetch(CHAT_HOST, "GET", path, { headers: { "Unidentified-Access-Key": toBase64(accessKey) }, signal: ctx.signal }) : undefined;
	if (res && (res.status === 401 || res.status === 403)) {
		refused = "refused";
		res = undefined;
	}
	res ??= await signalFetch(CHAT_HOST, "GET", path, { headers: { Authorization: ctx.auth }, signal: ctx.signal });
	if (res.status === 404) return refused; // no such device (or account); the server's 409 will tell
	if (res.status !== 200) throw new Error(`GET /v2/keys/${serviceId}/${device} failed: HTTP ${res.status}`);
	const keys = JSON.parse(dec.decode(res.body)) as KeysResponse;
	const identityKey = fromBase64(keys.identityKey);
	const check = await ctx.identities.check(serviceId, identityKey);
	if (check === "changed") store.resetIdentityStore(); // else libsignal rejects the new key until restart
	for (const d of keys.devices) {
		if (isSelf && d.deviceId === ctx.ourDeviceId) continue;
		if (!d.signedPreKey || !d.pqPreKey) throw new Error(`device ${d.deviceId} of ${serviceId} has no signed or Kyber prekey`);
		await sig.processPreKeyBundle(
			addr(d.deviceId),
			local(),
			d.registrationId,
			sig.WasmPublicKey.deserialize(identityKey),
			d.signedPreKey.keyId,
			sig.WasmPublicKey.deserialize(fromBase64(d.signedPreKey.publicKey)),
			fromBase64(d.signedPreKey.signature),
			d.preKey?.keyId,
			d.preKey ? fromBase64(d.preKey.publicKey) : undefined,
			d.pqPreKey.keyId,
			fromBase64(d.pqPreKey.publicKey),
			fromBase64(d.pqPreKey.signature),
			store.sessions,
			store.identityStore,
		);
		await store.saveSession(serviceId, d.deviceId);
	}
	if (check !== "same") await ctx.identities.save(serviceId, identityKey);
	if (check === "changed") (ctx.identityChanges ??= []).push(serviceId);
	return refused;
}

/** Device lists from a 409 (mismatched) or 410 (stale) answer to a send. */
export type DeviceMismatch = { missingDevices?: number[]; extraDevices?: number[]; staleDevices?: number[] };

/**
 * Desktop handleMismatchedDevicesError / handleStaleDevicesError: on 409 drop the extra devices'
 * sessions and fetch keys for the missing ones; on 410 archive the stale sessions and fetch new keys.
 */
export async function repairDevices(store: ProtocolStore, serviceId: string, status: 409 | 410, m: DeviceMismatch, fetch: (device: number) => Promise<void>): Promise<void> {
	const sig = signal();
	const addr = (d: number) => new sig.WasmProtocolAddress(serviceId, d);
	if (status === 409) {
		for (const d of m.extraDevices ?? []) {
			await store.sessions.delete_session(addr(d));
			await store.saveSession(serviceId, d);
		}
		for (const d of m.missingDevices ?? []) await fetch(d);
		return;
	}
	for (const d of m.staleDevices ?? []) {
		await store.sessions.archive_session(addr(d));
		await store.saveSession(serviceId, d);
		await fetch(d);
	}
}

/**
 * The recorded identity key for `serviceId`, else the one in our session with one of `devices`:
 * sessions made before identity keys were recorded still carry the key libsignal trusted for them.
 * A key found that way is recorded (as if first seen), so later sends and checks have it.
 */
export async function identityFor(ctx: SendContext, serviceId: string, devices: number[]): Promise<Uint8Array | undefined> {
	const recorded = await ctx.identities.get(serviceId);
	if (recorded) return recorded;
	const sig = signal();
	for (const device of devices) {
		const record = await ctx.store.sessions.export_session(new sig.WasmProtocolAddress(serviceId, device));
		if (!record) continue;
		let key: Uint8Array | undefined;
		try {
			key = libsignalExtra().session_remote_identity(record);
		} catch {
			continue;
		}
		if (key?.length !== 33) continue;
		await ctx.identities.save(serviceId, key);
		return key;
	}
	return undefined;
}

/**
 * Encrypts `content` for every device of `serviceId` (minus our own device when sending to
 * ourselves) and delivers it, repairing the device list on 409/410 as Desktop does.
 * Returns the device ids it was delivered to.
 */
export async function sendToServiceId(ctx: SendContext, serviceId: string, content: Uint8Array, timestamp: number, opts: SendOptions = {}): Promise<number[]> {
	const sig = signal();
	const { store } = ctx;
	const isSelf = serviceId === ctx.ourAci;
	const plaintext = opts.plaintext ? content : padMessage(content);
	const addr = (device: number) => new sig.WasmProtocolAddress(serviceId, device);
	const local = () => new sig.WasmProtocolAddress(ctx.ourAci, ctx.ourDeviceId);

	const processKeys = async (device: number | "*") => {
		if ((await fetchKeys(ctx, serviceId, device, wantSealed ? opts.accessKey : undefined)) === "refused") {
			// The same key would be refused for the PUT too: this send goes authenticated.
			ctx.onAccessKeyRefused?.(serviceId, opts.accessKey!);
			wantSealed = false;
		}
	};

	// Never sealed to ourselves: our own devices know who we are. Plaintext (retry requests) is sealed too.
	let wantSealed = !!(opts.accessKey && ctx.sealedSender && !isSelf);
	if (!isSelf && !wantSealed) ctx.onUnsealed?.(serviceId, !opts.accessKey ? "no access key" : "no certificate");
	let reportedNoIdentity = false;

	let devices = (await store.sessionDevices(serviceId)).filter((d) => !(isSelf && d === ctx.ourDeviceId));
	if (!devices.length) {
		await processKeys("*");
		devices = (await store.sessionDevices(serviceId)).filter((d) => !(isSelf && d === ctx.ourDeviceId));
		// Our own account with no other device (a standalone primary without linked devices): nobody to send to.
		if (isSelf && !devices.length) return [];
	}

	for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
		// Read each attempt: a key fetch in the previous one may have recorded a changed key.
		// None recorded (e.g. a session from before identities were recorded): this attempt goes authenticated.
		const theirIdentity = wantSealed ? await identityFor(ctx, serviceId, devices) : undefined;
		const sealed = !!theirIdentity;
		if (wantSealed && !sealed && !reportedNoIdentity) {
			ctx.onUnsealed?.(serviceId, "no identity key");
			reportedNoIdentity = true;
		}
		const messages = [];
		let sealFailed = false;
		for (const device of devices) {
			// Plaintext (retry requests) still needs the device's registration id, from our session with it.
			let inner: { type: number; body: Uint8Array; envelopeType: number };
			let registrationId: number | undefined;
			if (opts.plaintext) {
				registrationId = await store.sessions.session_remote_registration_id(addr(device));
				// Sealed (as Desktop does for retry requests), the inner message is the PlaintextContent itself.
				inner = { type: CIPHERTEXT_PLAINTEXT, body: plaintext, envelopeType: ENVELOPE_PLAINTEXT_CONTENT };
			} else {
				const ct = await sig.encryptMessage(plaintext, addr(device), local(), store.sessions, store.identityStore);
				registrationId = await store.sessions.session_remote_registration_id(addr(device));
				await store.saveSession(serviceId, device);
				inner = { type: ct.message_type, body: ct.body, envelopeType: ct.message_type === sig.message_type_pre_key() ? ENVELOPE_PREKEY_MESSAGE : ENVELOPE_DOUBLE_RATCHET };
				ct.free();
			}
			let body = inner.body;
			if (sealed) {
				const s = ctx.sealedSender!;
				try {
					body = libsignalExtra().seal(serviceId, device, theirIdentity!, s.identityKeyPair, s.certificate, inner.type, inner.body, opts.contentHint ?? 0, opts.groupId);
				} catch (e) {
					// e.g. an unreadable recorded identity key or certificate: send authenticated instead.
					console.error(`sealing for ${serviceId}.${device} failed; sending authenticated`, e);
					sealFailed = true;
					break;
				}
			}
			messages.push({
				type: sealed ? ENVELOPE_UNIDENTIFIED_SENDER : inner.envelopeType,
				destinationDeviceId: device,
				destinationRegistrationId: registrationId,
				content: toBase64(body),
			});
		}
		if (sealFailed) {
			// One request is all sealed or all authenticated: encrypt again (the ratchet just moves on).
			wantSealed = false;
			attempt--;
			continue;
		}

		const res = await signalFetch(CHAT_HOST, "PUT", `/v1/messages/${serviceId}?story=false`, {
			// Sealed: the access key instead of our credentials, so the server can't tell who sent it.
			headers: sealed ? { "Unidentified-Access-Key": toBase64(opts.accessKey!) } : { Authorization: ctx.auth },
			json: { messages, timestamp, online: false, urgent: opts.urgent ?? true },
			signal: ctx.signal,
		});
		if (res.status === 200) {
			if (sealed) (ctx.sealedTo ??= []).push(serviceId);
			// Delivered: a send-log failure only costs a later resend, so it mustn't fail the send.
			if (!opts.plaintext) await ctx.sendLog?.save(serviceId, timestamp, content, opts.groupId).catch((e) => console.error("send log save failed", e));
			return devices;
		}

		const err = (() => {
			try {
				return JSON.parse(dec.decode(res.body)) as DeviceMismatch;
			} catch {
				return {};
			}
		})();
		if (sealed && (res.status === 401 || res.status === 403)) {
			// Wrong or outdated access key (profile key changed, or they restrict sealed sender): fall back.
			ctx.onAccessKeyRefused?.(serviceId, opts.accessKey!);
			wantSealed = false;
			attempt--;
			continue;
		}
		if (res.status === 409 || res.status === 410) {
			await repairDevices(store, serviceId, res.status, err, processKeys);
		} else {
			throw new Error(`PUT /v1/messages/${serviceId} failed: HTTP ${res.status} ${dec.decode(res.body).slice(0, 300)}`);
		}
		devices = (await store.sessionDevices(serviceId)).filter((d) => !(isSelf && d === ctx.ourDeviceId));
	}
	throw new Error(`sending to ${serviceId}: device list still mismatched after ${MAX_ATTEMPTS} attempts`);
}
