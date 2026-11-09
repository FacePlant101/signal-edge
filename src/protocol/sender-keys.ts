// Sender-key group sends, as Signal-Desktop ts/util/sendToGroup.preload.ts does them: our sender key
// for the group (one distribution id per group) is shared once with each member device in a
// SenderKeyDistributionMessage; after that a group message is encrypted once (`encryptGroupMessage`),
// sealed for every member device in one sealed-sender v2 message, and sent in one
// `PUT /v1/messages/multi_recipient`, authorized by a token combined from the group send endorsements
// the groups server issued with the group state (no access keys). The caller falls back to one
// message per member when this path can't be used (fewer than two recipients, no endorsements, no
// sender certificate) or fails.

import type { SqlDatabase } from "../sql.js";
import { signalFetch } from "../net/http.js";
import { concat, dec, fromBase64, toBase64 } from "../util/bytes.js";
import { encode } from "./proto.js";
import { CONTENT_HINT, libsignalExtra } from "./sealed.js";
import { fetchKeys, identityFor, padMessage, repairDevices, sendToServiceId, type DeviceMismatch, type SendContext } from "./sender.js";
import { CHAT_HOST } from "./socket.js";
import { signal } from "./wasm.js";

/** Desktop MAX_SENDER_KEY_EXPIRE_DURATION: a new key (new distribution id) at least this often. */
const SENDER_KEY_MAX_AGE_MS = 90 * 24 * 3600 * 1000;
const MAX_ATTEMPTS = 4;
/** Endorsements this close to expiring aren't used (the server checks the token's expiration). */
const ENDORSEMENT_MARGIN_S = 60;

type Device = { aci: string; device: number; registrationId: number };
export type SenderKeyInfo = { distributionId: string; createdAt: number; devices: Device[] };

const SCHEMA = ["CREATE TABLE IF NOT EXISTS sender_key_shares (group_id TEXT PRIMARY KEY, distribution_id TEXT NOT NULL, created_at INTEGER NOT NULL, devices TEXT NOT NULL)"];

export function createSenderKeySchema(sql: SqlDatabase): void {
	for (const stmt of SCHEMA) sql.exec(stmt);
}

/** Per group: our distribution id and which member devices already hold our sender key (Desktop senderKeyInfo). */
export class SenderKeyShares {
	constructor(private readonly sql: SqlDatabase) {}

	get(groupId: string): SenderKeyInfo | undefined {
		const row = this.sql.exec<{ distribution_id: string; created_at: number; devices: string }>("SELECT distribution_id, created_at, devices FROM sender_key_shares WHERE group_id = ?", groupId)[0];
		return row && { distributionId: row.distribution_id, createdAt: row.created_at, devices: JSON.parse(row.devices) };
	}

	put(groupId: string, info: SenderKeyInfo): void {
		this.sql.exec("INSERT OR REPLACE INTO sender_key_shares (group_id, distribution_id, created_at, devices) VALUES (?, ?, ?, ?)", groupId, info.distributionId, info.createdAt, JSON.stringify(info.devices));
	}

	/** A device asked for a sender-key message again: it lacks our key, so the next send shares it anew (Desktop does this on retry requests). */
	forgetDevice(aci: string, device: number): void {
		for (const row of this.sql.exec<{ group_id: string; devices: string }>("SELECT group_id, devices FROM sender_key_shares")) {
			const held: Device[] = JSON.parse(row.devices);
			const devices = held.filter((d) => !(d.aci === aci && d.device === device));
			if (devices.length !== held.length) this.sql.exec("UPDATE sender_key_shares SET devices = ? WHERE group_id = ?", JSON.stringify(devices), row.group_id);
		}
	}
}

export type SenderKeySend = {
	ctx: SendContext;
	groupId: string; // base64
	masterKey: Uint8Array;
	/** Every current member (ACIs); a member who had our key and left forces a new key. */
	members: string[];
	/** Who this send should reach this way (members other than us). */
	recipients: string[];
	endorsements: { expiration: number; members: string[]; data: string };
	/** Unpadded Content; the same bytes go into the send log per recipient. */
	content: Uint8Array;
	timestamp: number;
	/** For the 1:1 key-sharing messages and key fetches, when we have them. */
	accessKeys: Map<string, Uint8Array | undefined>;
	shares: SenderKeyShares;
};

export type SenderKeyResult = { delivered: string[]; unregistered: string[]; sharedWith: number };

/**
 * Whether the group's endorsements allow this path at all (still valid, covering at least two
 * recipients); it also needs a sender certificate. Otherwise the caller sends one message per member.
 */
export function senderKeyUsable(recipients: string[], e: SenderKeySend["endorsements"] | undefined): e is SenderKeySend["endorsements"] {
	if (!e || e.expiration - Date.now() / 1000 < ENDORSEMENT_MARGIN_S) return false;
	return recipients.filter((a) => e.members.includes(a)).length >= 2; // Desktop fails over below two
}

/** Throws when the multi-recipient send can't be done; nothing reached anyone then (the caller falls back). */
export async function sendWithSenderKey(p: SenderKeySend): Promise<SenderKeyResult> {
	const sig = signal();
	const x = libsignalExtra();
	const { ctx, shares } = p;
	const store = ctx.store;
	const sealedSender = ctx.sealedSender;
	if (!sealedSender) throw new Error("no sender certificate");
	const local = () => new sig.WasmProtocolAddress(ctx.ourAci, ctx.ourDeviceId);
	const addr = (aci: string, device: number) => new sig.WasmProtocolAddress(aci, device);
	const groupIdBytes = fromBase64(p.groupId);
	const recipients = [...new Set(p.recipients)].filter((a) => a !== ctx.ourAci && p.endorsements.members.includes(a));

	// A new key when the old one is too old or a member who had it has left (Desktop resetSenderKey).
	let info = shares.get(p.groupId);
	if (!info || Date.now() - info.createdAt > SENDER_KEY_MAX_AGE_MS || info.devices.some((d) => !p.members.includes(d.aci))) {
		info = { distributionId: crypto.randomUUID(), createdAt: Date.now(), devices: [] };
		shares.put(p.groupId, info);
	}

	// A key fetch the server refuses with this access key: remember that (as sendToServiceId does), and
	// don't offer the same key again in this send.
	const keysFor = async (aci: string, device: number | "*") => {
		const accessKey = p.accessKeys.get(aci);
		if ((await fetchKeys(ctx, aci, device, accessKey)) === "refused") {
			ctx.onAccessKeyRefused?.(aci, accessKey!);
			p.accessKeys.set(aci, undefined);
		}
	};
	// Every device of `aci` with a live session, with its registration id.
	const devicesOf = async (aci: string): Promise<Device[]> => {
		const out: Device[] = [];
		for (const device of await store.sessionDevices(aci)) {
			const registrationId = await store.sessions.session_remote_registration_id(addr(aci, device));
			if (registrationId !== undefined) out.push({ aci, device, registrationId });
		}
		return out;
	};
	// Key-sharing sends report safety-number changes into the caller's list, but they aren't group
	// deliveries (sealedTo) and aren't resendable (sendLog).
	const shareCtx: SendContext = { ...ctx, sendLog: undefined, sealedTo: undefined, identityChanges: (ctx.identityChanges ??= []) };

	let sharedWith = 0;
	for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
		// Every recipient device with a live session, and its identity key (needed to seal for it).
		let devices: Device[] = [];
		const identityKeys = new Map<string, Uint8Array>();
		for (const aci of recipients) {
			if (!(await store.sessionDevices(aci)).length) await keysFor(aci, "*");
			const key = await identityFor(ctx, aci, await store.sessionDevices(aci));
			if (!key) continue;
			devices.push(...(await devicesOf(aci)));
			identityKeys.set(aci, key);
		}

		// Share our key with devices that don't hold it yet (new members, new or re-registered devices).
		// A member it can't be shared with (e.g. unregistered) is left out of this message and gets a
		// message of their own from the caller; the others still go in one request.
		const same = (a: Device, b: Device) => a.aci === b.aci && a.device === b.device && a.registrationId === b.registrationId;
		const fresh = devices.filter((d) => !info!.devices.some((k) => same(k, d)));
		const unshared = new Set<string>();
		if (fresh.length) {
			const skdm = await sig.createSenderKeyDistribution(local(), info.distributionId, store.senderKeys);
			await store.saveSenderKey(ctx.ourAci, ctx.ourDeviceId, info.distributionId, true);
			for (const aci of new Set(fresh.map((d) => d.aci))) {
				let shared = false;
				try {
					await sendToServiceId(shareCtx, aci, encode([[7, skdm]]), Date.now(), { accessKey: p.accessKeys.get(aci), contentHint: CONTENT_HINT.IMPLICIT, groupId: groupIdBytes });
					shared = true;
					sharedWith++;
				} catch (e) {
					unshared.add(aci);
					console.warn(`sharing our sender key with ${aci} failed; they get a message of their own`, e);
				}
				// That send may have repaired their device list; it reached every device it ends with.
				devices = [...devices.filter((d) => d.aci !== aci), ...(shared ? await devicesOf(aci) : [])];
			}
		}
		// Devices that went away stay out of the shared list (they would get the key again if they return);
		// those of a member we couldn't share with now stay listed, so their leaving still forces a new key.
		// Saved as soon as the key is shared, so a failure below doesn't share it again.
		info = { ...info, devices: [...devices, ...info.devices.filter((k) => unshared.has(k.aci))] };
		shares.put(p.groupId, info);
		const reached = [...new Set(devices.map((d) => d.aci))];
		if (reached.length < 2) throw new Error("fewer than two recipients with sessions, identity keys and our sender key");

		// One encryption for everyone, sealed per device.
		const skm = await sig.encryptGroupMessage(local(), info.distributionId, padMessage(p.content), store.senderKeys);
		await store.saveSenderKey(ctx.ourAci, ctx.ourDeviceId, info.distributionId, true);
		const sorted = devices.slice().sort((a, b) => (a.aci < b.aci ? -1 : a.aci > b.aci ? 1 : a.device - b.device));
		const sessions: Uint8Array[] = [];
		for (const d of sorted) {
			const record = await store.sessions.export_session(addr(d.aci, d.device));
			if (!record) throw new Error(`session for ${d.aci}.${d.device} vanished`);
			sessions.push(record);
		}
		const body = x.seal_multi_recipient(
			sorted.map((d) => d.aci),
			new Uint32Array(sorted.map((d) => d.device)),
			concat(...sorted.map((d) => identityKeys.get(d.aci)!)),
			concat(...sessions),
			new Uint32Array(sessions.map((s) => s.length)),
			sealedSender.identityKeyPair,
			sealedSender.certificate,
			skm,
			CONTENT_HINT.RESENDABLE,
			groupIdBytes,
		);

		// The token covers exactly the accounts in this message.
		const e = p.endorsements;
		const all = fromBase64(e.data);
		const size = all.length / e.members.length;
		const picked = reached.map((aci) => {
			const i = e.members.indexOf(aci);
			return all.subarray(i * size, (i + 1) * size);
		});
		const token = x.group_send_full_token(concat(...picked), picked.length, x.group_params(p.masterKey).secret_params, e.expiration);

		const res = await signalFetch(CHAT_HOST, "PUT", `/v1/messages/multi_recipient?ts=${p.timestamp}&online=false&urgent=true&story=false`, {
			headers: { "Group-Send-Token": toBase64(token), "Content-Type": "application/vnd.signal-messenger.mrm" },
			body,
			signal: p.ctx.signal,
		});
		const json = () => {
			try {
				return JSON.parse(dec.decode(res.body)) as unknown;
			} catch {
				return undefined;
			}
		};
		if (res.status === 200) {
			const unregistered = ((json() as { uuids404?: string[] } | undefined)?.uuids404 ?? []).map((u) => u.toLowerCase());
			const delivered = reached.filter((a) => !unregistered.includes(a));
			for (const aci of delivered) {
				await ctx.sendLog?.save(aci, p.timestamp, p.content, groupIdBytes).catch((err) => console.error("send log save failed", err));
				(ctx.sealedTo ??= []).push(aci);
			}
			return { delivered, unregistered, sharedWith };
		}
		if (res.status === 409 || res.status === 410) {
			// Per account, as for a 1:1 send: drop extra devices, fetch missing ones, renew stale ones; try again.
			for (const entry of (json() as { uuid: string; devices?: DeviceMismatch }[] | undefined) ?? []) {
				const aci = entry.uuid.toLowerCase();
				await repairDevices(store, aci, res.status, entry.devices ?? {}, (d) => keysFor(aci, d));
			}
			continue;
		}
		throw new Error(`PUT /v1/messages/multi_recipient failed: HTTP ${res.status} ${dec.decode(res.body).slice(0, 200)}`);
	}
	throw new Error(`multi-recipient send: device lists still mismatched after ${MAX_ATTEMPTS} attempts`);
}
