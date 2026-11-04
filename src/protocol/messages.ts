// Decrypted chat history in DO SQLite. Routing metadata (conversation, author,
// timestamps) stays queryable; the message itself is sealed JSON.

import { dec, enc } from "../util/bytes.js";
import type { SqlDatabase } from "../sql.js";
import type { Sealer } from "../util/sealer.js";
import type { MessageRecord } from "./content.js";

const SCHEMA = [
	`CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		server_guid TEXT,
		conversation TEXT NOT NULL,
		author TEXT NOT NULL,
		sent_at INTEGER NOT NULL,
		received_at INTEGER NOT NULL,
		kind TEXT NOT NULL,
		data BLOB NOT NULL
	)`,
	// One envelope can yield one record per kind; redelivered envelopes are ignored.
	"CREATE UNIQUE INDEX IF NOT EXISTS messages_guid ON messages (server_guid, kind) WHERE server_guid IS NOT NULL",
	"CREATE INDEX IF NOT EXISTS messages_conversation ON messages (conversation, sent_at)",
];

export function createMessageSchema(sql: SqlDatabase): void {
	for (const stmt of SCHEMA) sql.exec(stmt);
}

export type StoredMessage = MessageRecord & { id: number; receivedAt: number };
export type Conversation = { conversation: string; messages: number; lastSentAt: number; lastAuthor: string };

export class MessageStore {
	constructor(
		private readonly sql: SqlDatabase,
		private readonly sealer: Sealer,
	) {}

	async add(records: MessageRecord[], serverGuid: string | undefined, receivedAt: number): Promise<number> {
		// A resent copy (after a retry request) has a new server guid but the same author and timestamp.
		const fresh = records.filter(
			(r) => r.kind === "identity-change" || !(r.sentAt > 0) || !this.sql.exec("SELECT 1 FROM messages WHERE conversation = ? AND sent_at = ? AND author = ? AND kind = ? LIMIT 1", r.conversation, r.sentAt, r.author, r.kind).length,
		);
		const rows = await Promise.all(fresh.map(async (r) => [r, await this.sealer.seal(aad(r), enc.encode(JSON.stringify(r)))] as const));
		let added = 0;
		for (const [r, sealed] of rows) {
			// RETURNING yields a row only when the insert happened (rowsWritten counts ignored ones too).
			const inserted = this.sql.exec(
				"INSERT OR IGNORE INTO messages (server_guid, conversation, author, sent_at, received_at, kind, data) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
				serverGuid ?? null,
				r.conversation,
				r.author,
				r.sentAt,
				receivedAt,
				r.kind,
				sealed,
			);
			added += inserted.length;
		}
		return added;
	}

	async get(id: number): Promise<StoredMessage | undefined> {
		const row = this.sql.exec<Row>("SELECT id, conversation, author, sent_at, received_at, kind, data FROM messages WHERE id = ?", id)[0];
		if (!row) return undefined;
		const rec = JSON.parse(dec.decode(await this.sealer.open(aadOf(row), new Uint8Array(row.data)))) as MessageRecord;
		return { ...rec, id: row.id, receivedAt: row.received_at };
	}

	async latest(limit: number, conversation?: string): Promise<StoredMessage[]> {
		const q = conversation
			? this.sql.exec<Row>("SELECT id, conversation, author, sent_at, received_at, kind, data FROM messages WHERE conversation = ? ORDER BY sent_at DESC LIMIT ?", conversation, limit)
			: this.sql.exec<Row>("SELECT id, conversation, author, sent_at, received_at, kind, data FROM messages ORDER BY received_at DESC LIMIT ?", limit);
		const out: StoredMessage[] = [];
		for (const row of q) {
			const rec = JSON.parse(dec.decode(await this.sealer.open(aadOf(row), new Uint8Array(row.data)))) as MessageRecord;
			out.push({ ...rec, id: row.id, receivedAt: row.received_at });
		}
		return out;
	}

	conversations(): Conversation[] {
		return this.sql
			.exec<{ conversation: string; messages: number; lastSentAt: number; lastAuthor: string }>(
				`SELECT conversation, COUNT(*) AS messages, MAX(sent_at) AS lastSentAt,
					(SELECT author FROM messages m2 WHERE m2.conversation = m.conversation ORDER BY sent_at DESC LIMIT 1) AS lastAuthor
				 FROM messages m GROUP BY conversation ORDER BY lastSentAt DESC`,
			);
	}

	count(): number {
		return this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM messages")[0]?.n ?? 0;
	}
}

type Row = { id: number; conversation: string; author: string; sent_at: number; received_at: number; kind: string; data: ArrayBuffer };

function aad(r: MessageRecord): string {
	return `messages|${r.conversation}|${r.author}|${r.sentAt}|${r.kind}`;
}

function aadOf(row: Row): string {
	return `messages|${row.conversation}|${row.author}|${row.sent_at}|${row.kind}`;
}
