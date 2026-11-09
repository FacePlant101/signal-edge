import type { SqlDatabase } from "../sql.js";

/** The self-tests write test rows and drop tables: never on a database holding an account. */
export function refuseLinkedDatabase(db: SqlDatabase): void {
	let linked = false;
	try {
		linked = db.exec("SELECT 1 FROM kv WHERE key = 'account_secrets'").length > 0;
	} catch {
		// no kv table: not an account database
	}
	if (linked) throw new Error("refusing to run a self-test on a database that holds a linked account");
}
