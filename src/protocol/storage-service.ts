// Read-only storage-service client: the account's group list (master keys) and contact names,
// which a linked device otherwise only learns from traffic. Ported from Signal-Desktop
// ts/services/storage.preload.ts, ts/Crypto.node.ts (key derivation) and protos/SignalStorage.proto.

import { signalFetch } from "../net/http.js";
import { concat, dec, enc, toBase64 } from "../util/bytes.js";
import { uuidString } from "./content.js";
import { Decoded, encode } from "./proto.js";
import { CHAT_HOST } from "./socket.js";

export const STORAGE_HOST = "storage.signal.org";

const RECORD = { CONTACT: 1, GROUPV2: 3 } as const;
/** Desktop MAX_READ_KEYS. */
const READ_BATCH = 2500;

export type StorageGroup = { masterKey: Uint8Array; blocked: boolean; archived: boolean };
export type StorageContact = {
	aci: string;
	e164?: string;
	pni?: string;
	/** Best display name: nickname, then the phone's contact name, then the profile name. */
	name?: string;
	profileName?: string;
	username?: string;
	blocked: boolean;
	hidden: boolean;
	profileKey?: Uint8Array;
};
export type StorageSnapshot = { version: number; groups: StorageGroup[]; contacts: StorageContact[] };

/** Reads the whole storage manifest and the group and contact records it lists. */
export async function readStorage(chatAuth: string, masterKey: Uint8Array): Promise<StorageSnapshot> {
	const res = await signalFetch(CHAT_HOST, "GET", "/v1/storage/auth", { headers: { Authorization: chatAuth } });
	if (res.status !== 200) throw new Error(`GET /v1/storage/auth failed: HTTP ${res.status}`);
	const { username, password } = JSON.parse(dec.decode(res.body)) as { username: string; password: string };
	const auth = `Basic ${btoa(`${username}:${password}`)}`;

	const storageKey = await hmacSha256(masterKey, enc.encode("Storage Service Encryption"));
	const m = await signalFetch(STORAGE_HOST, "GET", "/v1/storage/manifest", { headers: { Authorization: auth } });
	if (m.status === 404) return { version: 0, groups: [], contacts: [] }; // nothing stored yet
	if (m.status !== 200) throw new Error(`GET /v1/storage/manifest failed: HTTP ${m.status}`);
	const manifest = new Decoded(m.body);
	const version = manifest.bigint(1) ?? 0n;
	const manifestKey = await hmacSha256(storageKey, enc.encode(`Manifest_${version}`));
	const record = new Decoded(await aesGcmOpen(manifestKey, manifest.bytes(2) ?? new Uint8Array(0)));
	const recordIkm = record.bytes(4);

	const wanted = (record.fields.get(2) ?? [])
		.filter((v): v is Uint8Array => v instanceof Uint8Array)
		.map((id) => new Decoded(id))
		.filter((id) => id.uint(2) === RECORD.CONTACT || id.uint(2) === RECORD.GROUPV2)
		.map((id) => id.bytes(1)!)
		.filter(Boolean);

	const snapshot: StorageSnapshot = { version: Number(version), groups: [], contacts: [] };
	for (let i = 0; i < wanted.length; i += READ_BATCH) {
		const read = encode(wanted.slice(i, i + READ_BATCH).map((k) => [1, k] as [number, Uint8Array]));
		const r = await signalFetch(STORAGE_HOST, "PUT", "/v1/storage/read", {
			headers: { Authorization: auth, "Content-Type": "application/x-protobuf" },
			body: read,
		});
		if (r.status !== 200) throw new Error(`PUT /v1/storage/read failed: HTTP ${r.status}`);
		for (const item of new Decoded(r.body).fields.get(1) ?? []) {
			if (!(item instanceof Uint8Array)) continue;
			const it = new Decoded(item);
			const key = it.bytes(1);
			const value = it.bytes(2);
			if (!key || !value) continue;
			const itemKey = recordIkm
				? await hkdf32(recordIkm, concat(enc.encode("20240801_SIGNAL_STORAGE_SERVICE_ITEM_"), key))
				: await hmacSha256(storageKey, enc.encode(`Item_${toBase64(key)}`));
			const rec = new Decoded(await aesGcmOpen(itemKey, value));
			const group = rec.bytes(RECORD.GROUPV2);
			const contact = rec.bytes(RECORD.CONTACT);
			if (group) {
				const g = new Decoded(group);
				const masterKey = g.bytes(1);
				if (masterKey?.length === 32) snapshot.groups.push({ masterKey, blocked: g.bool(2) ?? false, archived: g.bool(4) ?? false });
			} else if (contact) {
				const c = parseContact(new Decoded(contact));
				if (c) snapshot.contacts.push(c);
			}
		}
	}
	return snapshot;
}

function parseContact(c: Decoded): StorageContact | undefined {
	const aciBinary = c.bytes(25);
	const aci = (c.string(1) || (aciBinary?.length === 16 ? uuidString(aciBinary) : "")).toLowerCase();
	if (!aci) return undefined; // e164/PNI-only contacts can't be messaged by ACI
	const join = (...parts: (string | undefined)[]) => parts.filter((p) => p?.trim()).join(" ") || undefined;
	const nick = c.bytes(22) && new Decoded(c.bytes(22)!);
	const profileName = join(c.string(6), c.string(7));
	const pniBinary = c.bytes(26);
	return {
		aci,
		e164: c.string(2) || undefined,
		pni: c.string(15) || (pniBinary?.length === 16 ? uuidString(pniBinary) : undefined),
		name: join(nick?.string(1), nick?.string(2)) || c.string(19) || join(c.string(17), c.string(18)) || profileName,
		profileName,
		username: c.string(8) || undefined,
		blocked: c.bool(9) ?? false,
		hidden: c.bool(20) ?? false,
		profileKey: c.bytes(3)?.length === 32 ? c.bytes(3) : undefined,
	};
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

async function hkdf32(ikm: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
	const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
	return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info }, k, 256));
}

/** Desktop decryptProfile: 12-byte IV, then AES-256-GCM ciphertext and tag. */
async function aesGcmOpen(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	if (data.length < 12 + 16) throw new Error("storage record too short");
	const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.subarray(0, 12) }, k, data.subarray(12)));
}
