// Retry requests ("please resend"), as Signal's apps do it. When we can't decrypt a message, we
// send its sender an unencrypted PlaintextContent { DecryptionErrorMessage } naming the message
// (timestamp, the sending device, and for 1:1 messages the ratchet key it used). When a contact
// can't decrypt one of ours, the same request comes back to us: we archive the session if its
// ratchet key matches, then resend the message from a short send log, or send a null message so
// the next message starts a fresh session.
// Wire formats: libsignal rust/protocol/src/protocol.rs (DecryptionErrorMessage::for_original,
// PlaintextContent) and proto/service.proto. Behaviour: Signal-Desktop ts/util/handleRetry.preload.ts.

import type { SqlDatabase } from "../sql.js";
import type { Sealer } from "../util/sealer.js";
import { CIPHERTEXT } from "./content.js";
import { Decoded, encode } from "./proto.js";
import { randomPadding } from "./sender.js";
import { signal } from "./wasm.js";

/** What we know about a message that failed to decrypt once its sealed-sender layer was removed. */
export type FailedMessage = {
	sender: string;
	device: number;
	/** CiphertextMessageType (CIPHERTEXT.*) of the inner message. */
	type: number;
	ciphertext: Uint8Array;
	/** The sender's timestamp for the message (Envelope.timestamp). */
	timestamp?: number;
	/** Our identity it was addressed to. */
	ours: "aci" | "pni";
	/** Group id from its sealed layer, carried back in a sealed retry request (as Desktop). */
	groupId?: Uint8Array;
};

/** A decrypt failure that carries enough to ask the sender for the message again. */
export class DecryptFailure extends Error {
	constructor(
		readonly failed: FailedMessage,
		cause: unknown,
	) {
		super(`decrypting ${failed.type === CIPHERTEXT.SENDER_KEY ? "sender-key" : failed.type === CIPHERTEXT.PREKEY ? "PreKey" : "Whisper"} message from ${failed.sender}.${failed.device}: ${cause}`);
	}
}

export type DecryptionError = { ratchetKey?: Uint8Array; timestamp?: number; deviceId?: number };

/** DecryptionErrorMessage::for_original: the ratchet key for 1:1 messages, none for sender-key ones. */
export function decryptionErrorFor(failed: FailedMessage): Uint8Array {
	const sig = signal();
	if (failed.timestamp === undefined) throw new Error("no timestamp to name the message");
	let ratchetKey: Uint8Array | undefined;
	if (failed.type === CIPHERTEXT.WHISPER || failed.type === CIPHERTEXT.PREKEY) {
		const wasmType = failed.type === CIPHERTEXT.PREKEY ? sig.message_type_pre_key() : sig.message_type_signal();
		ratchetKey = sig.ratchet_key_of_ciphertext(failed.ciphertext, wasmType);
		if (!ratchetKey) throw new Error("no ratchet key in a 1:1 message");
	} else if (failed.type !== CIPHERTEXT.SENDER_KEY) {
		throw new Error(`can't ask for a resend of message type ${failed.type}`);
	}
	return encode([[1, ratchetKey], [2, failed.timestamp], [3, failed.device]]);
}

export function parseDecryptionError(buf: Uint8Array): DecryptionError {
	const m = new Decoded(buf);
	return { ratchetKey: m.bytes(1), timestamp: m.uint(2), deviceId: m.uint(3) };
}

/** PlaintextContent: 0xC0, Content { decryptionErrorMessage (8) }, 0x80. Sent unencrypted (envelope type 8). */
export function plaintextContent(decryptionError: Uint8Array): Uint8Array {
	const content = encode([[8, decryptionError]]);
	const out = new Uint8Array(content.length + 2);
	out[0] = 0xc0;
	out.set(content, 1);
	out[out.length - 1] = 0x80;
	return out;
}

/** Content { nullMessage { padding } } (Desktop MessageSender.getNullMessage): opens a fresh session. */
export function nullMessageContent(): Uint8Array {
	return encode([[4, encode([[1, randomPadding()]])]]);
}

// --- storage: the send log, and envelopes already processed ---

/** How long sent messages can be resent (Desktop keeps its send log for a day). */
export const SEND_LOG_MS = 24 * 3600 * 1000;
/** How long processed envelope ids are remembered, to spot redeliveries. */
const SEEN_MS = 7 * 24 * 3600 * 1000;

const SCHEMA = [
	// content: the unpadded Content as sent to that recipient, sealed; group_id for the sealed layer of a resend.
	"CREATE TABLE IF NOT EXISTS send_log (recipient TEXT NOT NULL, timestamp INTEGER NOT NULL, sent_at INTEGER NOT NULL, content BLOB NOT NULL, group_id BLOB, PRIMARY KEY (recipient, timestamp))",
	"CREATE INDEX IF NOT EXISTS send_log_sent_at ON send_log (sent_at)",
	"CREATE TABLE IF NOT EXISTS seen_envelopes (server_guid TEXT PRIMARY KEY, at INTEGER NOT NULL)",
	"CREATE INDEX IF NOT EXISTS seen_envelopes_at ON seen_envelopes (at)",
];

export function createRetrySchema(sql: SqlDatabase): void {
	for (const stmt of SCHEMA) sql.exec(stmt);
	// send_log tables created before group_id existed: CREATE TABLE IF NOT EXISTS leaves them as they are.
	const columns = sql.exec<{ name: string }>("PRAGMA table_info(send_log)");
	if (!columns.some((c) => c.name === "group_id")) sql.exec("ALTER TABLE send_log ADD COLUMN group_id BLOB");
}

export class SendLog {
	constructor(
		private readonly sql: SqlDatabase,
		private readonly sealer: Sealer,
	) {}

	async save(recipient: string, timestamp: number, content: Uint8Array, groupId?: Uint8Array): Promise<void> {
		const sealed = await this.sealer.seal(aad(recipient, timestamp), content);
		this.sql.exec(
			"INSERT OR REPLACE INTO send_log (recipient, timestamp, sent_at, content, group_id) VALUES (?, ?, ?, ?, ?)",
			recipient,
			timestamp,
			Date.now(),
			sealed,
			groupId ?? null,
		);
	}

	async get(recipient: string, timestamp: number): Promise<{ content: Uint8Array; groupId?: Uint8Array } | undefined> {
		const row = this.sql
			.exec<{ content: ArrayBuffer; sent_at: number; group_id: ArrayBuffer | null }>("SELECT content, sent_at, group_id FROM send_log WHERE recipient = ? AND timestamp = ?", recipient, timestamp)
			[0];
		if (!row || Date.now() - row.sent_at > SEND_LOG_MS) return undefined;
		const content = await this.sealer.open(aad(recipient, timestamp), new Uint8Array(row.content));
		return { content, groupId: row.group_id ? new Uint8Array(row.group_id) : undefined };
	}
}

export function sendLogCount(sql: SqlDatabase): number {
	return sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM send_log")[0]?.n ?? 0;
}

function aad(recipient: string, timestamp: number): string {
	return `send_log|${recipient}|${timestamp}`;
}

/** Envelope ids we already processed: a redelivered one would fail to decrypt (its keys are used up). */
export class SeenEnvelopes {
	constructor(private readonly sql: SqlDatabase) {}

	has(serverGuid: string | undefined): boolean {
		return !!serverGuid && this.sql.exec("SELECT 1 FROM seen_envelopes WHERE server_guid = ?", serverGuid).length > 0;
	}

	add(serverGuid: string | undefined): void {
		if (serverGuid) this.sql.exec("INSERT OR IGNORE INTO seen_envelopes (server_guid, at) VALUES (?, ?)", serverGuid, Date.now());
	}
}

/** Drops send-log entries and seen ids past their retention. */
export function pruneRetryState(sql: SqlDatabase, now = Date.now()): void {
	sql.exec("DELETE FROM send_log WHERE sent_at < ?", now - SEND_LOG_MS);
	sql.exec("DELETE FROM seen_envelopes WHERE at < ?", now - SEEN_MS);
}

// --- rate limits (in memory; a restarted instance starts over) ---

/** Sliding-window counter per key. */
export class Limiter {
	#hits = new Map<string, { windowMs: number; at: number[] }>();

	/** Whether allow() would let one more hit through, without counting it. */
	wouldAllow(limits: { key: string; max: number; windowMs: number }[], now = Date.now()): boolean {
		return limits.every((l) => (this.#hits.get(l.key)?.at ?? []).filter((t) => now - t < l.windowMs).length < l.max);
	}

	/** Allows (and counts) one hit only if every limit has room, so a refusal uses up none of them. */
	allow(limits: { key: string; max: number; windowMs: number }[], now = Date.now()): boolean {
		const current = limits.map((l) => ({ ...l, at: (this.#hits.get(l.key)?.at ?? []).filter((t) => now - t < l.windowMs) }));
		const ok = current.every((l) => l.at.length < l.max);
		for (const l of current) {
			if (ok) l.at.push(now);
			this.#hits.set(l.key, { windowMs: l.windowMs, at: l.at });
		}
		// Each key is pruned by its own window (a per-message 24 h limit must outlive hourly ones).
		if (this.#hits.size > 1000) for (const [k, v] of this.#hits) if (!v.at.some((t) => now - t < v.windowMs)) this.#hits.delete(k);
		return ok;
	}
}
