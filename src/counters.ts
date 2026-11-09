// Counters and last errors that survive restarts. Every deploy restarts the Durable Object, and
// merging to main deploys, so the in-memory receive counters started over each time and a feature
// that worked once (a sealed send, a retry request answered) left no trace. These are kept in
// SQLite: a total per counter with when it first and last moved, and the last error per area.
// `reset` (Forget account) wipes them with everything else.

import type { SqlDatabase } from "./sql.js";
const SCHEMA = [
	"CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, total INTEGER NOT NULL, first_at INTEGER NOT NULL, last_at INTEGER NOT NULL)",
	"CREATE TABLE IF NOT EXISTS last_errors (area TEXT PRIMARY KEY, at INTEGER NOT NULL, message TEXT NOT NULL)",
];

/** Longest error text kept; enough to recognise it, not a log. */
const MAX_ERROR_CHARS = 300;

export function createCounterSchema(sql: SqlDatabase): void {
	for (const stmt of SCHEMA) sql.exec(stmt);
}

export type LastingCounter = { total: number; firstAt: number; lastAt: number };
export type LastError = { at: number; message: string };

export class Counters {
	constructor(private readonly sql: SqlDatabase) {}

	bump(name: string, n = 1, now = Date.now()): void {
		if (!n) return;
		this.sql.exec(
			"INSERT INTO counters (name, total, first_at, last_at) VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET total = total + excluded.total, last_at = excluded.last_at",
			name,
			n,
			now,
			now,
		);
	}

	error(area: string, message: string, now = Date.now()): void {
		this.sql.exec("INSERT OR REPLACE INTO last_errors (area, at, message) VALUES (?, ?, ?)", area, now, message.slice(0, MAX_ERROR_CHARS));
	}

	counters(): Record<string, LastingCounter> {
		const out: Record<string, LastingCounter> = {};
		for (const r of this.sql.exec<{ name: string; total: number; first_at: number; last_at: number }>("SELECT name, total, first_at, last_at FROM counters ORDER BY name")) {
			out[r.name] = { total: r.total, firstAt: r.first_at, lastAt: r.last_at };
		}
		return out;
	}

	errors(): Record<string, LastError> {
		const out: Record<string, LastError> = {};
		for (const r of this.sql.exec<{ area: string; at: number; message: string }>("SELECT area, at, message FROM last_errors ORDER BY area")) {
			out[r.area] = { at: r.at, message: r.message };
		}
		return out;
	}
}

/** The counters that say whether each feature has worked on the real account, grouped for a status line. */
export const FEATURE_COUNTERS: { label: string; names: string[] }[] = [
	{ label: "received", names: ["receive:envelopes", "receive:stored", "receive:failed"] },
	{
		label: "sends",
		names: [
			"send:sealed",
			"send:authenticated",
			"sealed-sender:skipped (no access key)",
			"sealed-sender:skipped (no identity key)",
			"sealed-sender:skipped (no certificate)",
			"sealed-sender:access key refused",
			"sealed-sender:no certificate",
		],
	},
	{ label: "sender keys", names: ["send:sender-key", "send:sender-key failed"] },
	{ label: "attachments", names: ["send:attachments uploaded", "receive:long text expanded", "receive:long text not expanded"] },
	{ label: "retry requests", names: ["retry-request:sent", "retry-request:received", "retry-request:resent", "retry-request:null message sent", "retry-request:failed"] },
	{ label: "timers", names: ["timer:updated"] },
	{ label: "identity", names: ["identity-change"] },
];

/** "sends: send:sealed 3 (last 2026-11-05 07:12), …" lines for the counters that have moved. */
export function describeCounters(counters: Record<string, LastingCounter>, errors: Record<string, LastError>): string[] {
	const when = (t: number) => new Date(t).toISOString().slice(0, 16).replace("T", " ");
	const lines: string[] = [];
	for (const { label, names } of FEATURE_COUNTERS) {
		const parts = names.filter((n) => counters[n]).map((n) => `${n.replace(/^[^:]+:/, "")} ${counters[n]!.total} (last ${when(counters[n]!.lastAt)} UTC)`);
		if (parts.length) lines.push(`${label}: ${parts.join(", ")}`);
	}
	for (const [area, e] of Object.entries(errors)) lines.push(`last ${area} error (${when(e.at)} UTC): ${e.message}`);
	return lines;
}
