// Durable libsignal state: signal-wasm's in-memory stores, hydrated from and
// written back to SQLite (SqlDatabase). Every record is sealed (AES-GCM) with
// an AAD naming its table and key.

import type { SqlDatabase } from "../sql.js";
import type * as Sig from "@getmaapp/signal-wasm";
import type { Sealer } from "../util/sealer.js";
import { toBase64 } from "../util/bytes.js";
import { signal } from "./wasm.js";

/**
 * Other people's sender keys kept per sending device (one per group it sends to us in, plus
 * rotations); the least recently used go first. A message under a pruned key fails to decrypt, and
 * the retry request that follows makes the sender share it again. Our own keys aren't capped.
 */
const MAX_SENDER_KEYS_PER_DEVICE = 256;

/** Which of our two identities a store belongs to. */
export type OurIdentity = "aci" | "pni";

export type UploadPreKey = { keyId: number; publicKey: string };
export type UploadSignedPreKey = { keyId: number; publicKey: string; signature: string };

const SCHEMA = [
	"CREATE TABLE IF NOT EXISTS prekeys (identity TEXT NOT NULL, id INTEGER NOT NULL, record BLOB NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (identity, id))",
	"CREATE TABLE IF NOT EXISTS signed_prekeys (identity TEXT NOT NULL, id INTEGER NOT NULL, record BLOB NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (identity, id))",
	"CREATE TABLE IF NOT EXISTS kyber_prekeys (identity TEXT NOT NULL, id INTEGER NOT NULL, record BLOB NOT NULL, created_at INTEGER NOT NULL, last_resort INTEGER NOT NULL, PRIMARY KEY (identity, id))",
	"CREATE TABLE IF NOT EXISTS kyber_usage (identity TEXT PRIMARY KEY, data BLOB NOT NULL)",
	"CREATE TABLE IF NOT EXISTS sessions (identity TEXT NOT NULL, address TEXT NOT NULL, record BLOB NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (identity, address))",
	"CREATE TABLE IF NOT EXISTS sender_keys (address TEXT NOT NULL, distribution_id TEXT NOT NULL, record BLOB NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (address, distribution_id))",
	"CREATE TABLE IF NOT EXISTS key_counters (identity TEXT NOT NULL, kind TEXT NOT NULL, next_id INTEGER NOT NULL, PRIMARY KEY (identity, kind))",
];

export function createStoreSchema(sql: SqlDatabase): void {
	for (const stmt of SCHEMA) sql.exec(stmt);
}

/** Desktop keeps this many newest signed / last-resort keys regardless of age. */
const KEEP_NEWEST = 5;
/** Older keys beyond KEEP_NEWEST go once messages encrypted to them can no longer be queued. */
const KEY_RETENTION_MS = 45 * 24 * 3600 * 1000;
/** Signal-Desktop PRE_KEY_ARCHIVE_AGE. */
const ONE_TIME_KEY_MAX_AGE_MS = 90 * 24 * 3600 * 1000;
const MAX_KEY_ID = 0xffffff;

type Row = { record: ArrayBuffer };
type KeyTable = "prekeys" | "signed_prekeys" | "kyber_prekeys";

export class ProtocolStore {
	#identityStore: Sig.WasmInMemIdentityKeyStore;
	readonly sessions: Sig.WasmInMemSessionStore;
	readonly preKeys: Sig.WasmInMemPreKeyStore;
	readonly signedPreKeys: Sig.WasmInMemSignedPreKeyStore;
	readonly kyberPreKeys: Sig.WasmInMemKyberPreKeyStore;
	readonly senderKeys: Sig.WasmInMemSenderKeyStore;

	private constructor(
		private readonly db: SqlDatabase,
		private readonly sealer: Sealer,
		readonly ours: OurIdentity,
		private readonly identityKeyPair: Uint8Array,
		readonly registrationId: number,
	) {
		const sig = signal();
		this.#identityStore = new sig.WasmInMemIdentityKeyStore(sig.WasmIdentityKeyPair.deserialize(identityKeyPair), registrationId);
		this.sessions = new sig.WasmInMemSessionStore();
		this.preKeys = new sig.WasmInMemPreKeyStore();
		this.signedPreKeys = new sig.WasmInMemSignedPreKeyStore();
		this.kyberPreKeys = new sig.WasmInMemKyberPreKeyStore();
		this.senderKeys = new sig.WasmInMemSenderKeyStore();
	}

	/** libsignal's TOFU cache of remote identity keys; the persistent record is src/signal/identities.ts. */
	get identityStore(): Sig.WasmInMemIdentityKeyStore {
		return this.#identityStore;
	}

	/**
	 * Forgets the cached remote identity keys. The in-memory store rejects a contact's changed key
	 * until restart; once IdentityLog has accepted the change, this lets libsignal take it.
	 */
	resetIdentityStore(): void {
		const sig = signal();
		this.#identityStore.free();
		this.#identityStore = new sig.WasmInMemIdentityKeyStore(sig.WasmIdentityKeyPair.deserialize(this.identityKeyPair), this.registrationId);
	}

	/** Builds the in-memory stores for one identity from SQLite. */
	static async load(db: SqlDatabase, sealer: Sealer, ours: OurIdentity, identityKeyPair: Uint8Array, registrationId: number): Promise<ProtocolStore> {
		const s = new ProtocolStore(db, sealer, ours, identityKeyPair, registrationId);
		const sql = db;
		for (const r of sql.exec<{ id: number } & Row>("SELECT id, record FROM prekeys WHERE identity = ?", ours)) {
			await s.preKeys.import_pre_key(r.id, await s.#open("prekeys", r.id, r.record));
		}
		for (const r of sql.exec<{ id: number } & Row>("SELECT id, record FROM signed_prekeys WHERE identity = ?", ours)) {
			await s.signedPreKeys.import_signed_pre_key(r.id, await s.#open("signed_prekeys", r.id, r.record));
		}
		for (const r of sql.exec<{ id: number } & Row>("SELECT id, record FROM kyber_prekeys WHERE identity = ?", ours)) {
			await s.kyberPreKeys.import_kyber_pre_key(r.id, await s.#open("kyber_prekeys", r.id, r.record));
		}
		const usage = sql.exec<{ data: ArrayBuffer }>("SELECT data FROM kyber_usage WHERE identity = ?", ours)[0];
		if (usage) s.kyberPreKeys.import_kyber_usage(await s.#open("kyber_usage", "", usage.data));
		for (const r of sql.exec<{ address: string } & Row>("SELECT address, record FROM sessions WHERE identity = ?", ours)) {
			const [name, device] = splitAddress(r.address);
			await s.sessions.import_session(address(name, device), await s.#open("sessions", r.address, r.record));
		}
		// Sender keys belong to the ACI: groups never address our PNI.
		if (ours === "aci") {
			for (const r of sql.exec<{ address: string; distribution_id: string } & Row>("SELECT address, distribution_id, record FROM sender_keys")) {
				const [name, device] = splitAddress(r.address);
				await s.senderKeys.import_sender_key(address(name, device), r.distribution_id, await s.#open("sender_keys", `${r.address}|${r.distribution_id}`, r.record));
			}
		}
		return s;
	}

	/** A fresh serialized identity key pair, since wasm-bindgen may consume arguments. */
	identityPair(): Sig.WasmIdentityKeyPair {
		return signal().WasmIdentityKeyPair.deserialize(this.identityKeyPair);
	}

	// --- writes after protocol operations ---

	/** Persists the session for name.device after an encrypt or decrypt. */
	async saveSession(name: string, device: number): Promise<void> {
		const write = await this.#sessionWrite(name, device);
		this.db.transaction(write);
	}

	/**
	 * After decryptMessage: persists the session and tombstones the prekeys the
	 * decrypt consumed, in one transaction. One-time keys are deleted so a
	 * restart can't resurrect them; last-resort Kyber use is recorded for
	 * anti-replay instead (see WasmDecryptResult docs).
	 */
	async afterDecrypt(name: string, device: number, result: Sig.WasmDecryptResult): Promise<void> {
		const writes = [await this.#sessionWrite(name, device)];
		const oneTime = result.oneTimePreKeyId;
		if (oneTime !== undefined) writes.push(() => this.db.exec("DELETE FROM prekeys WHERE identity = ? AND id = ?", this.ours, oneTime));
		const kyberId = result.kyberPreKeyId;
		if (kyberId !== undefined) {
			const row = this.db.exec<{ last_resort: number }>("SELECT last_resort FROM kyber_prekeys WHERE identity = ? AND id = ?", this.ours, kyberId)[0];
			if (row && !row.last_resort) {
				this.kyberPreKeys.remove_kyber_pre_key(kyberId);
				writes.push(() => this.db.exec("DELETE FROM kyber_prekeys WHERE identity = ? AND id = ?", this.ours, kyberId));
			} else {
				const sealed = await this.#seal("kyber_usage", "", this.kyberPreKeys.export_kyber_usage());
				writes.push(() => this.db.exec("INSERT OR REPLACE INTO kyber_usage (identity, data) VALUES (?, ?)", this.ours, sealed));
			}
		}
		this.db.transaction(() => writes.forEach((w) => w()));
	}

	/** Device ids of `name` with a live session (archived records, e.g. after a 410, don't count). */
	async sessionDevices(name: string): Promise<number[]> {
		const rows = this.db.exec<{ address: string }>("SELECT address FROM sessions WHERE identity = ? AND address LIKE ?", this.ours, `${name}.%`);
		const out: number[] = [];
		for (const { address: a } of rows) {
			const [n, device] = splitAddress(a);
			if (n === name && (await this.sessions.session_remote_registration_id(address(n, device))) !== undefined) out.push(device);
		}
		return out.sort((x, y) => x - y);
	}

	/** Saves a sender key after use; `ours`: our own sending key, never pruned (a lost one breaks our sends). */
	async saveSenderKey(name: string, device: number, distributionId: string, ours = false): Promise<void> {
		const key = `${name}.${device}`;
		const record = await this.senderKeys.export_sender_key(address(name, device), distributionId);
		if (!record) return;
		const sealed = await this.#seal("sender_keys", `${key}|${distributionId}`, record);
		this.db.exec("INSERT OR REPLACE INTO sender_keys (address, distribution_id, record, updated_at) VALUES (?, ?, ?, ?)", key, distributionId, sealed, Date.now());
		if (ours) return;
		// Anyone can send distribution messages with new ids: keep each device's newest ones only.
		this.db.exec(
			"DELETE FROM sender_keys WHERE address = ? AND distribution_id NOT IN (SELECT distribution_id FROM sender_keys WHERE address = ? ORDER BY updated_at DESC LIMIT ?)",
			key,
			key,
			MAX_SENDER_KEYS_PER_DEVICE,
		);
	}

	async #sessionWrite(name: string, device: number): Promise<() => void> {
		const key = `${name}.${device}`;
		const record = await this.sessions.export_session(address(name, device));
		if (!record) return () => this.db.exec("DELETE FROM sessions WHERE identity = ? AND address = ?", this.ours, key);
		const sealed = await this.#seal("sessions", key, record);
		return () => this.db.exec("INSERT OR REPLACE INTO sessions (identity, address, record, updated_at) VALUES (?, ?, ?, ?)", this.ours, key, sealed, Date.now());
	}

	// --- our prekeys ---

	/** One-time X25519 prekeys, stored before they are returned for upload. */
	async generatePreKeys(count: number): Promise<UploadPreKey[]> {
		const start = this.#reserveIds("prekey", count);
		const keys = await signal().generatePreKeys(start, count, this.preKeys);
		const rows = await Promise.all(keys.map(async (k) => [k.id, await this.#seal("prekeys", k.id, k.record)] as const));
		const now = Date.now();
		this.db.transaction(() => {
			for (const [id, sealed] of rows) this.db.exec("INSERT OR REPLACE INTO prekeys (identity, id, record, created_at) VALUES (?, ?, ?, ?)", this.ours, id, sealed, now);
		});
		return keys.map((k) => ({ keyId: k.id, publicKey: toBase64(k.public_key) }));
	}

	/** One-time Kyber prekeys (lastResort = false) or a single last-resort key. */
	async generateKyberPreKeys(count: number, lastResort = false): Promise<UploadSignedPreKey[]> {
		const start = this.#reserveIds("kyber", count);
		const out: UploadSignedPreKey[] = [];
		const rows: (readonly [number, Uint8Array])[] = [];
		for (let i = 0; i < count; i++) {
			const k = await signal().generateKyberPreKey(start + i, this.identityPair(), this.kyberPreKeys);
			rows.push([k.id, await this.#seal("kyber_prekeys", k.id, k.record)]);
			out.push({ keyId: k.id, publicKey: toBase64(k.public_key), signature: toBase64(k.signature) });
		}
		const now = Date.now();
		this.db.transaction(() => {
			for (const [id, sealed] of rows) {
				this.db.exec("INSERT OR REPLACE INTO kyber_prekeys (identity, id, record, created_at, last_resort) VALUES (?, ?, ?, ?, ?)", this.ours, id, sealed, now, lastResort ? 1 : 0);
			}
		});
		return out;
	}

	async generateSignedPreKey(): Promise<UploadSignedPreKey> {
		const id = this.#reserveIds("signed", 1);
		const k = await signal().generateSignedPreKey(id, this.identityPair(), this.signedPreKeys);
		const sealed = await this.#seal("signed_prekeys", k.id, k.record);
		this.db.exec("INSERT OR REPLACE INTO signed_prekeys (identity, id, record, created_at) VALUES (?, ?, ?, ?)", this.ours, k.id, sealed, Date.now());
		return { keyId: k.id, publicKey: toBase64(k.public_key), signature: toBase64(k.signature) };
	}

	/** Adds a key record generated elsewhere (the ones uploaded while linking). */
	async importKey(table: "signed_prekeys" | "kyber_prekeys", id: number, record: Uint8Array, createdAt: number): Promise<void> {
		if (table === "signed_prekeys") {
			await this.signedPreKeys.import_signed_pre_key(id, record);
			const sealed = await this.#seal(table, id, record);
			this.db.exec("INSERT OR REPLACE INTO signed_prekeys (identity, id, record, created_at) VALUES (?, ?, ?, ?)", this.ours, id, sealed, createdAt);
		} else {
			await this.kyberPreKeys.import_kyber_pre_key(id, record);
			const sealed = await this.#seal(table, id, record);
			this.db.exec("INSERT OR REPLACE INTO kyber_prekeys (identity, id, record, created_at, last_resort) VALUES (?, ?, ?, ?, 1)", this.ours, id, sealed, createdAt);
		}
	}

	/** Deletes keys that were generated but never published (their upload failed). */
	discardKeys(ids: Partial<Record<KeyTable, number[] | undefined>>): void {
		this.db.transaction(() => {
			for (const [table, list] of Object.entries(ids) as [KeyTable, number[] | undefined][]) {
				for (const id of list ?? []) {
					this.db.exec(`DELETE FROM ${table} WHERE identity = ? AND id = ?`, this.ours, id);
					if (table === "kyber_prekeys") this.kyberPreKeys.remove_kyber_pre_key(id);
				}
			}
		});
	}

	/** Creation time of the newest signed key, or newest last-resort Kyber key. */
	newestKey(kind: "signed" | "last_resort"): number | undefined {
		const q =
			kind === "signed"
				? "SELECT MAX(created_at) AS t FROM signed_prekeys WHERE identity = ?"
				: "SELECT MAX(created_at) AS t FROM kyber_prekeys WHERE identity = ? AND last_resort = 1";
		return this.db.exec<{ t: number | null }>(q, this.ours)[0]?.t ?? undefined;
	}

	/** Drops old signed and last-resort keys (keeping the newest KEEP_NEWEST of each) and stale one-time keys. */
	cleanupOldKeys(): number {
		const cutoff = Date.now() - KEY_RETENTION_MS;
		let removed = 0;
		const prune = (table: KeyTable, where: string) => {
			const rows = this.db.exec<{ id: number; created_at: number }>(`SELECT id, created_at FROM ${table} WHERE identity = ? ${where} ORDER BY created_at DESC`, this.ours);
			for (const { id, created_at } of rows.slice(KEEP_NEWEST)) {
				if (created_at >= cutoff) continue;
				this.db.exec(`DELETE FROM ${table} WHERE identity = ? AND id = ?`, this.ours, id);
				if (table === "kyber_prekeys") this.kyberPreKeys.remove_kyber_pre_key(id);
				removed++;
			}
		};
		prune("signed_prekeys", "");
		prune("kyber_prekeys", "AND last_resort = 1");

		// One-time keys nobody used within Desktop's PRE_KEY_ARCHIVE_AGE (replaced on the server, or never uploaded).
		const oneTimeCutoff = Date.now() - ONE_TIME_KEY_MAX_AGE_MS;
		for (const table of ["prekeys", "kyber_prekeys"] as const) {
			const where = table === "kyber_prekeys" ? "AND last_resort = 0" : "";
			const old = this.db.exec<{ id: number }>(`SELECT id FROM ${table} WHERE identity = ? ${where} AND created_at < ?`, this.ours, oneTimeCutoff);
			for (const { id } of old) {
				this.db.exec(`DELETE FROM ${table} WHERE identity = ? AND id = ?`, this.ours, id);
				if (table === "kyber_prekeys") this.kyberPreKeys.remove_kyber_pre_key(id);
				removed++;
			}
		}
		return removed;
	}

	count(table: KeyTable | "sessions", where = ""): number {
		return this.db.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM ${table} WHERE identity = ? ${where}`, this.ours)[0]?.n ?? 0;
	}

	/** Reserves `count` consecutive 24-bit key ids (wrapping, never 0). */
	#reserveIds(kind: "prekey" | "kyber" | "signed", count: number): number {
		const row = this.db.exec<{ next_id: number }>("SELECT next_id FROM key_counters WHERE identity = ? AND kind = ?", this.ours, kind)[0];
		// Start at a random id like Desktop, so ids from a relink don't collide with old ones.
		let start = row?.next_id ?? wrapId(crypto.getRandomValues(new Uint32Array(1))[0]! & MAX_KEY_ID);
		if (start + count > MAX_KEY_ID) start = 1; // keep each batch contiguous and within 24 bits
		this.db.exec("INSERT OR REPLACE INTO key_counters (identity, kind, next_id) VALUES (?, ?, ?)", this.ours, kind, wrapId(start + count));
		return start;
	}

	#seal(table: string, key: string | number, data: Uint8Array): Promise<Uint8Array> {
		return this.sealer.seal(`${table}|${this.ours}|${key}`, data);
	}

	#open(table: string, key: string | number, data: ArrayBuffer): Promise<Uint8Array> {
		return this.sealer.open(`${table}|${this.ours}|${key}`, new Uint8Array(data));
	}
}

function wrapId(id: number): number {
	return (id % MAX_KEY_ID) || 1;
}

/** "serviceId.deviceId" → [serviceId, deviceId]; service ids contain no dots. */
function splitAddress(a: string): [string, number] {
	const i = a.lastIndexOf(".");
	return [a.slice(0, i), Number(a.slice(i + 1))];
}

function address(name: string, device: number): Sig.WasmProtocolAddress {
	return new (signal().WasmProtocolAddress)(name, device);
}
