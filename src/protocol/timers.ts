// Disappearing-message timers per chat, so our messages carry the chat's timer. Without one, Android
// treats a 1:1 message as a timer change and turns disappearing messages off for that chat
// (DataMessageProcessor.handlePossibleExpirationUpdate with a null version); in groups our messages
// just wouldn't disappear. The timer is learned from every DataMessage in the chat, theirs and our
// phone's sync transcripts, with Desktop's version rules (ConversationModel.updateExpirationTimer):
// version 0 never changes it, an older version is ignored. Group timers come from group state
// (GroupRecord.disappearingTimer); what is seen here is the fallback.

import type { SqlDatabase } from "../sql.js";
/** A timer as seen in one DataMessage (expireTimer 5, expireTimerVersion 23). */
export type TimerSeen = { conversation: string; expireTimer: number; version?: number };

/** What to put in an outgoing DataMessage. */
export type Expiry = { expireTimer?: number; version?: number };

const SCHEMA = ["CREATE TABLE IF NOT EXISTS chat_timers (conversation TEXT PRIMARY KEY, expire_timer INTEGER NOT NULL, version INTEGER, updated_at INTEGER NOT NULL)"];

export function createTimerSchema(sql: SqlDatabase): void {
	for (const stmt of SCHEMA) sql.exec(stmt);
}

export class ChatTimers {
	constructor(private readonly sql: SqlDatabase) {}

	get(conversation: string): { expireTimer: number; version?: number } | undefined {
		const row = this.sql.exec<{ expire_timer: number; version: number | null }>("SELECT expire_timer, version FROM chat_timers WHERE conversation = ?", conversation)[0];
		return row && { expireTimer: row.expire_timer, version: row.version ?? undefined };
	}

	/** Records a timer seen in a message; returns whether it changed what we hold. */
	apply(seen: TimerSeen): boolean {
		const isGroup = seen.conversation.startsWith("group:");
		// Only chats we can send to (sync transcripts can name "unknown", e164: or pni: destinations).
		if (!isGroup && !seen.conversation.startsWith("aci:")) return false;
		const stored = this.get(seen.conversation);
		if (!isGroup) {
			if (seen.version === 0) return false; // "don't touch", as Desktop and Android read it
			if (seen.version === undefined && stored?.version !== undefined) return false; // a legacy sender can't override a versioned timer
			if (seen.version !== undefined && stored?.version !== undefined && seen.version < stored.version) return false;
		}
		const version = isGroup ? undefined : (seen.version ?? stored?.version);
		if (stored && stored.expireTimer === seen.expireTimer && stored.version === version) return false;
		this.sql.exec(
			"INSERT OR REPLACE INTO chat_timers (conversation, expire_timer, version, updated_at) VALUES (?, ?, ?, ?)",
			seen.conversation,
			seen.expireTimer,
			version ?? null,
			Date.now(),
		);
		return true;
	}

	/**
	 * The timer for a message we send. 1:1 with a known timer: that timer and its version (as Desktop
	 * sends). Unknown: version 0, which no client applies, so we can't switch a timer off by not knowing it.
	 * A timer learned only from version-less messages also goes out with version 0: without a version,
	 * Android would apply it as a timer change.
	 * Groups: the group state's timer, else the last one seen; groups have no versions.
	 */
	forSend(conversation: string, groupTimer?: number): Expiry {
		const stored = this.get(conversation);
		if (conversation.startsWith("group:")) return { expireTimer: groupTimer ?? stored?.expireTimer };
		if (!stored) return { version: 0 };
		return { expireTimer: stored.expireTimer, version: stored.version ?? 0 };
	}
}
