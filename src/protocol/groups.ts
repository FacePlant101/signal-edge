// Groups (v2): auth credentials, group state from the groups server, and the local directory
// of groups and contacts. Ported from Signal-Desktop ts/services/groupCredentialFetcher.preload.ts,
// ts/groups.preload.ts (decryptGroupState), ts/textsecure/WebAPI.preload.ts (getGroup) and
// protos/Groups.proto. zkgroup itself runs in our libsignal build (sealed/src/zk.rs).

import type { SqlDatabase } from "../sql.js";
import { signalFetch } from "../net/http.js";
import { dec, enc, fromBase64, toBase64 } from "../util/bytes.js";
import type { Sealer } from "../util/sealer.js";
import { Decoded } from "./proto.js";
import { libsignalExtra } from "./sealed.js";
import { CHAT_HOST } from "./socket.js";
import { STORAGE_HOST, type StorageContact } from "./storage-service.js";

/** Signal-Desktop config/production.json serverPublicParams (zkgroup ServerPublicParams). */
const SERVER_PUBLIC_PARAMS = fromBase64(
	"AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P+NameAZYOD12qRkxosQQP5uux6B2nRyZ7sAV54DgFyLiRcq1FvwKw2EPQdk4HDoePrO/RNUbyNddnM/mMgj4FW65xCoT1LmjrIjsv/Ggdlx46ueczhMgtBunx1/w8k8V+l8LVZ8gAT6wkU5J+DPQalQguMg12Jzug3q4TbdHiGCmD9EunCwOmsLuLJkz6EcSYXtrlDEnAM+hicw7iergYLLlMXpfTdGxJCWJmP4zqUFeTTmsmhsjGBt7NiEB/9pFFEB3pSbf4iiUukw63Eo8Aqnf4iwob6X1QviCWuc8t0LUlT9vALgh/f2DPVOOmR0RW6bgRvc7DSF20V/omg+YBw==",
);

const DAY_S = 24 * 3600;
/** Desktop fetches credentials for today plus six days. */
const CREDENTIAL_DAYS = 7;

/** profileKey (base64, from group state) is for sealed-sender access keys: never show it. */
export type GroupMember = { aci: string; admin: boolean; profileKey?: string };

/** One group in the local directory. The master key stays in local storage (sealed). */
export type GroupRecord = {
	id: string; // base64 group identifier; chat id is "group:<id>"
	masterKey: string; // base64
	source: "storage" | "message";
	blocked?: boolean;
	archived?: boolean;
	revision?: number;
	title?: string;
	description?: string;
	members?: GroupMember[];
	/** Invited, not yet accepted (by ACI or PNI). */
	pendingMembers?: string[];
	requestingMembers?: number;
	announcementsOnly?: boolean;
	terminated?: boolean;
	/**
	 * Group send endorsements (GroupResponse field 2), verified for `members` in that order: one
	 * serialized endorsement per member back to back (base64), valid until `expiration` (epoch
	 * seconds). They authorize sender-key sends (`Group-Send-Token`); never shown.
	 */
	endorsements?: { expiration: number; members: string[]; data: string };
	/** Disappearing-messages timer in seconds (0 or absent: off), from group state. */
	disappearingTimer?: number;
	fetchedAt?: number;
	fetchError?: string;
};

export type Credential = { redemptionTime: number; credential: string }; // seconds, base64

// --- groups server ---

export function groupIdFromMasterKey(masterKey: Uint8Array): string {
	return toBase64(libsignalExtra().group_params(masterKey).group_id);
}

/**
 * GET /v1/certificate/auth/group for today plus six days, verified for our ACI and PNI
 * (Desktop maybeFetchNewCredentials). Returns the received AuthCredentialWithPni per day.
 */
/**
 * Group auth credentials for the coming days. `authCredentialSalt`: accounts without a phone number
 * (no PNI) get credentials bound to it instead (Signal-Server issueAuthCredentialZkcWithoutPni).
 */
export async function fetchCredentials(chatAuth: string, aci: string, pni: string | undefined, authCredentialSalt?: Uint8Array): Promise<Credential[]> {
	const today = Math.floor(Date.now() / 1000 / DAY_S) * DAY_S;
	const end = today + (CREDENTIAL_DAYS - 1) * DAY_S;
	const res = await signalFetch(
		CHAT_HOST,
		"GET",
		`/v1/certificate/auth/group?redemptionStartSeconds=${today}&redemptionEndSeconds=${end}&v101=true&zkcCredential=true`,
		{ headers: { Authorization: chatAuth } },
	);
	if (res.status !== 200) throw new Error(`GET /v1/certificate/auth/group failed: HTTP ${res.status} ${dec.decode(res.body).slice(0, 200)}`);
	const body = JSON.parse(dec.decode(res.body)) as { pni?: string; credentials: Credential[] };
	const ourPni = body.pni ?? pni;
	const x = libsignalExtra();
	if (!ourPni) {
		if (!authCredentialSalt?.length) throw new Error("group credentials need our PNI, or the auth credential salt of an account without a phone number");
		return body.credentials.map((c) => ({
			redemptionTime: c.redemptionTime,
			credential: toBase64(x.receive_auth_credential_without_pni(SERVER_PUBLIC_PARAMS, aci, authCredentialSalt, c.redemptionTime, fromBase64(c.credential))),
		}));
	}
	return body.credentials.map((c) => ({
		redemptionTime: c.redemptionTime,
		credential: toBase64(x.receive_auth_credential(SERVER_PUBLIC_PARAMS, aci, ourPni.replace(/^PNI:/, ""), c.redemptionTime, fromBase64(c.credential))),
	}));
}

export function credentialForToday(credentials: Credential[]): Credential | undefined {
	const today = Math.floor(Date.now() / 1000 / DAY_S) * DAY_S;
	return credentials.find((c) => c.redemptionTime === today);
}

export class GroupFetchError extends Error {
	constructor(
		readonly status: number,
		message: string,
	) {
		super(message);
	}
}

/** GET storage.signal.org/v2/groups with a fresh credential presentation, decrypted (Desktop getGroup + decryptGroupState). */
export async function fetchGroupState(masterKey: Uint8Array, credential: Credential): Promise<Omit<GroupRecord, "id" | "masterKey" | "source">> {
	const x = libsignalExtra();
	const params = x.group_params(masterKey);
	const presentation = x.auth_presentation(SERVER_PUBLIC_PARAMS, params.secret_params, fromBase64(credential.credential));
	const auth = `Basic ${btoa(`${hex(params.public_params)}:${hex(presentation)}`)}`;
	const res = await signalFetch(STORAGE_HOST, "GET", "/v2/groups", { headers: { Authorization: auth, Accept: "application/x-protobuf" } });
	if (res.status === 403) throw new GroupFetchError(403, "not a member of this group (left, removed, or only invited)");
	if (res.status === 404) throw new GroupFetchError(404, "group not found");
	if (res.status !== 200) throw new GroupFetchError(res.status, `GET /v2/groups failed: HTTP ${res.status}`);

	const response = new Decoded(res.body);
	const group = new Decoded(response.bytes(1) ?? new Uint8Array(0));
	const secret = params.secret_params;
	const blob = (b: Uint8Array | undefined) => {
		if (!b?.length) return undefined;
		try {
			return new Decoded(x.decrypt_blob(secret, b));
		} catch {
			return undefined;
		}
	};
	const serviceId = (b: Uint8Array | undefined) => {
		if (!b?.length) return undefined;
		try {
			return x.decrypt_service_id(secret, b).toLowerCase().replace(/^pni:/, "PNI:");
		} catch {
			return undefined;
		}
	};
	const messages = (n: number) => (group.fields.get(n) ?? []).filter((v): v is Uint8Array => v instanceof Uint8Array).map((b) => new Decoded(b));

	const members: GroupMember[] = [];
	for (const m of messages(7)) {
		const aci = serviceId(m.bytes(1));
		if (!aci || aci.startsWith("PNI:")) continue;
		// Member.profileKey (3): lets us derive their access key for sealed-sender sends.
		let profileKey: string | undefined;
		try {
			const ct = m.bytes(3);
			if (ct?.length) profileKey = toBase64(x.decrypt_profile_key(secret, ct, aci));
		} catch {
			// unreadable or absent: sends to this member stay authenticated
		}
		members.push({ aci, admin: m.uint(2) === 2, profileKey });
	}
	// Disappearing-messages timer (4): absent means off; an unreadable blob is unknown (undefined), so
	// a send falls back to the timer seen in messages rather than turning it off.
	const timerBlob = group.bytes(4);
	const timer = timerBlob?.length ? blob(timerBlob) : undefined;
	// Endorsements for every member (us included), checked against the server's key; without them,
	// group sends fall back to one message per member.
	let endorsements: GroupRecord["endorsements"];
	const endorsementResponse = response.bytes(2);
	if (endorsementResponse?.length && members.length === messages(7).length) {
		try {
			const acis = members.map((m) => m.aci);
			const data = x.receive_group_send_endorsements(endorsementResponse, acis, Math.floor(Date.now() / 1000), secret, SERVER_PUBLIC_PARAMS);
			endorsements = { expiration: x.group_send_endorsements_expiration(endorsementResponse), members: acis, data: toBase64(data) };
		} catch (e) {
			console.warn("group send endorsements didn't verify", e);
		}
	}
	const pendingMembers = messages(8)
		.map((p) => serviceId(p.bytes(1) && new Decoded(p.bytes(1)!).bytes(1)))
		.filter((s): s is string => !!s);
	return {
		revision: group.uint(6) ?? 0,
		title: blob(group.bytes(2))?.string(1),
		description: blob(group.bytes(11))?.string(4),
		members,
		pendingMembers,
		requestingMembers: messages(9).length,
		announcementsOnly: group.bool(12) ?? false,
		disappearingTimer: !timerBlob?.length ? 0 : timer ? (timer.uint(3) ?? 0) : undefined,
		terminated: group.bool(14) ?? false,
		endorsements,
		fetchedAt: Date.now(),
	};
}

function hex(b: Uint8Array): string {
	return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// --- local directory (DO SQLite, sealed) ---

const SCHEMA = [
	"CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, data BLOB NOT NULL)",
	"CREATE TABLE IF NOT EXISTS contacts (aci TEXT PRIMARY KEY, data BLOB NOT NULL)",
];

export function createDirectorySchema(sql: SqlDatabase): void {
	for (const stmt of SCHEMA) sql.exec(stmt);
}

export type Contact = Omit<StorageContact, "profileKey"> & { profileKey?: string };

export class Directory {
	constructor(
		private readonly sql: SqlDatabase,
		private readonly sealer: Sealer,
	) {}

	async group(id: string): Promise<GroupRecord | undefined> {
		const row = this.sql.exec<{ data: ArrayBuffer }>("SELECT data FROM groups WHERE id = ?", id)[0];
		return row && JSON.parse(dec.decode(await this.sealer.open(`groups|${id}`, new Uint8Array(row.data))));
	}

	async groups(): Promise<GroupRecord[]> {
		const out: GroupRecord[] = [];
		for (const row of this.sql.exec<{ id: string; data: ArrayBuffer }>("SELECT id, data FROM groups")) {
			out.push(JSON.parse(dec.decode(await this.sealer.open(`groups|${row.id}`, new Uint8Array(row.data)))));
		}
		return out;
	}

	async putGroup(g: GroupRecord): Promise<void> {
		this.sql.exec("INSERT OR REPLACE INTO groups (id, data) VALUES (?, ?)", g.id, await this.sealer.seal(`groups|${g.id}`, enc.encode(JSON.stringify(g))));
	}

	async contacts(): Promise<Contact[]> {
		const out: Contact[] = [];
		for (const row of this.sql.exec<{ aci: string; data: ArrayBuffer }>("SELECT aci, data FROM contacts")) {
			out.push(JSON.parse(dec.decode(await this.sealer.open(`contacts|${row.aci}`, new Uint8Array(row.data)))));
		}
		return out;
	}

	/**
	 * Known profile keys (base64) of `aci`, distinct: the contact's first, then from the state of groups
	 * we share (`groups`, if the caller already has them, else read here).
	 */
	async profileKeys(aci: string, groups?: GroupRecord[]): Promise<string[]> {
		const keys = new Set<string>();
		const row = this.sql.exec<{ data: ArrayBuffer }>("SELECT data FROM contacts WHERE aci = ?", aci)[0];
		try {
			const contact: Contact | undefined = row && JSON.parse(dec.decode(await this.sealer.open(`contacts|${aci}`, new Uint8Array(row.data))));
			if (contact?.profileKey) keys.add(contact.profileKey);
		} catch (e) {
			// An unreadable contact record mustn't hide the keys in shared groups.
			console.error(`contact record for ${aci} unreadable`, e);
		}
		for (const g of groups ?? (await this.groups())) {
			const key = g.members?.find((m) => m.aci === aci)?.profileKey;
			if (key) keys.add(key);
		}
		return [...keys];
	}

	/** Replaces all contacts with the storage-service snapshot. */
	async replaceContacts(contacts: StorageContact[]): Promise<void> {
		const rows = await Promise.all(
			contacts.map(async (c) => {
				const stored: Contact = { ...c, profileKey: c.profileKey && toBase64(c.profileKey) };
				return [c.aci, await this.sealer.seal(`contacts|${c.aci}`, enc.encode(JSON.stringify(stored)))] as const;
			}),
		);
		this.sql.exec("DELETE FROM contacts");
		for (const [aci, data] of rows) this.sql.exec("INSERT OR REPLACE INTO contacts (aci, data) VALUES (?, ?)", aci, data);
	}
}
