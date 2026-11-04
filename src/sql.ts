/**
 * The storage the library needs: a synchronous SQLite database. Durable Object SQLite fits as is
 * (`durableObjectSql` in `signal-edge/workers`); so do `node:sqlite` and better-sqlite3.
 * BLOB columns may come back as ArrayBuffer or Uint8Array; the library accepts both.
 */
export type SqlValue = string | number | null | ArrayBuffer | Uint8Array;

export interface SqlDatabase {
	/** Runs one statement and returns its rows (empty for statements without results). */
	exec<T = Record<string, SqlValue>>(query: string, ...bindings: SqlValue[]): T[];
	/** Runs `fn` in a transaction: all of its statements are kept, or none. */
	transaction<T>(fn: () => T): T;
}

/** BLOB column value as bytes. */
export function blob(v: ArrayBuffer | Uint8Array): Uint8Array {
	return v instanceof Uint8Array ? v : new Uint8Array(v);
}
