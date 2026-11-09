// Remote identity keys (trust on first use), persisted ourselves: signal-wasm's
// WasmInMemIdentityKeyStore can't be exported or read. A contact's key reaches us in every
// PreKey message (a new session, which is how a changed key always arrives) and in every key
// bundle we fetch before sending, so those two places check and record it. Like Signal's apps,
// a changed key is accepted and reported ("safety number changed"), not blocked.

import type { SqlDatabase } from "../sql.js";
import { dec, enc, fromBase64, toBase64 } from "../util/bytes.js";
import type { Sealer } from "../util/sealer.js";
import { Decoded } from "./proto.js";

export type IdentityCheck = "new" | "same" | "changed";
type IdentityRecord = { key: string; firstSeen: number; changedAt?: number; changes?: number };

const SCHEMA = ["CREATE TABLE IF NOT EXISTS identities (service_id TEXT PRIMARY KEY, data BLOB NOT NULL)"];

export function createIdentitySchema(sql: SqlDatabase): void {
	for (const stmt of SCHEMA) sql.exec(stmt);
}

export class IdentityLog {
	constructor(
		private readonly sql: SqlDatabase,
		private readonly sealer: Sealer,
	) {}

	/** Compares a key with the recorded one without changing anything. */
	async check(serviceId: string, key: Uint8Array): Promise<IdentityCheck> {
		const r = await this.#get(serviceId);
		if (!r) return "new";
		return r.key === toBase64(key) ? "same" : "changed";
	}

	/** The recorded key (33 bytes), e.g. to seal a message to its owner. */
	async get(serviceId: string): Promise<Uint8Array | undefined> {
		const r = await this.#get(serviceId);
		return r && fromBase64(r.key);
	}

	/** Records a key once it has been used successfully (decrypted with, or sessions built from). */
	async save(serviceId: string, key: Uint8Array): Promise<void> {
		const r = await this.#get(serviceId);
		const k = toBase64(key);
		if (r?.key === k) return;
		const now = Date.now();
		const next: IdentityRecord = r ? { key: k, firstSeen: r.firstSeen, changedAt: now, changes: (r.changes ?? 0) + 1 } : { key: k, firstSeen: now };
		this.sql.exec(
			"INSERT OR REPLACE INTO identities (service_id, data) VALUES (?, ?)",
			serviceId,
			await this.sealer.seal(`identities|${serviceId}`, enc.encode(JSON.stringify(next))),
		);
	}

	count(): number {
		return this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM identities")[0]?.n ?? 0;
	}

	async #get(serviceId: string): Promise<IdentityRecord | undefined> {
		const row = this.sql.exec<{ data: ArrayBuffer }>("SELECT data FROM identities WHERE service_id = ?", serviceId)[0];
		return row && JSON.parse(dec.decode(await this.sealer.open(`identities|${serviceId}`, new Uint8Array(row.data))));
	}
}

/**
 * The sender's identity key in a serialized PreKeySignalMessage: a version byte, then protobuf field 3.
 * libsignal decodes the first 33 bytes (type 0x05 + key) and ignores anything after them, so that is
 * the key checked here too: otherwise a key with bytes appended would skip the identity check.
 */
export function preKeyMessageIdentity(ciphertext: Uint8Array): Uint8Array | undefined {
	try {
		const key = new Decoded(ciphertext.subarray(1)).bytes(3);
		return key && key.length >= 33 && key[0] === 0x05 ? key.slice(0, 33) : undefined;
	} catch {
		return undefined;
	}
}

