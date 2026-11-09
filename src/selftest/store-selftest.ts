// Persistence self-test for ProtocolStore. Runs inside a throwaway SignalAccount
// instance (never the real account): Bob's state lives in SQLite, Alice in memory.

import type { SqlDatabase } from "../sql.js";
import { refuseLinkedDatabase } from "./guard.js";
import type { Sealer } from "../util/sealer.js";
import { dec, enc, fromBase64 } from "../util/bytes.js";
import { createStoreSchema, ProtocolStore } from "../protocol/store.js";
import { signal } from "../protocol/wasm.js";

const BOB = "bob-aci";
const ALICE = "alice-aci";

export async function storeSelfTest(db: SqlDatabase, sealer: Sealer) {
	refuseLinkedDatabase(db);
	const sig = signal();
	const addr = (name: string) => new sig.WasmProtocolAddress(name, 1);
	createStoreSchema(db);

	// Bob: identity + prekeys in the durable store.
	const bobPriv = sig.WasmPrivateKey.generate();
	const bobPair = new sig.WasmIdentityKeyPair(bobPriv.getPublicKey(), sig.WasmPrivateKey.deserialize(bobPriv.serialize())).serialize();
	const bobRegId = sig.generateRegistrationId();
	let bob = await ProtocolStore.load(db, sealer, "aci", bobPair, bobRegId);
	const [opk] = await bob.generatePreKeys(1);
	const [kyber] = await bob.generateKyberPreKeys(1);
	const spk = await bob.generateSignedPreKey();
	const keysBefore = { preKeys: bob.count("prekeys"), kyber: bob.count("kyber_prekeys") };

	// Alice: in-memory party that starts a session from Bob's bundle.
	const alicePriv = sig.WasmPrivateKey.generate();
	const alicePair = new sig.WasmIdentityKeyPair(alicePriv.getPublicKey(), sig.WasmPrivateKey.deserialize(alicePriv.serialize()));
	const alice = {
		identity: new sig.WasmInMemIdentityKeyStore(alicePair, sig.generateRegistrationId()),
		sessions: new sig.WasmInMemSessionStore(),
		preKeys: new sig.WasmInMemPreKeyStore(),
		signed: new sig.WasmInMemSignedPreKeyStore(),
		kyber: new sig.WasmInMemKyberPreKeyStore(),
	};
	await sig.processPreKeyBundle(
		addr(BOB),
		addr(ALICE),
		bobRegId,
		sig.WasmIdentityKeyPair.deserialize(bobPair).public_key,
		spk.keyId,
		sig.WasmPublicKey.deserialize(fromBase64(spk.publicKey)),
		fromBase64(spk.signature),
		opk!.keyId,
		fromBase64(opk!.publicKey),
		kyber!.keyId,
		fromBase64(kyber!.publicKey),
		fromBase64(kyber!.signature),
		alice.sessions,
		alice.identity,
	);
	const aliceSend = (text: string) => sig.encryptMessage(enc.encode(text), addr(BOB), addr(ALICE), alice.sessions, alice.identity);
	const bobDecrypt = async (body: Uint8Array, type: number) => {
		const r = await sig.decryptMessage(body, type, addr(ALICE), addr(BOB), bob.sessions, bob.identityStore, bob.preKeys, bob.signedPreKeys, bob.kyberPreKeys);
		await bob.afterDecrypt(ALICE, 1, r);
		return dec.decode(r.plaintext);
	};

	// 1. First contact: consumes Bob's one-time prekey and one-time Kyber key.
	const m1 = await aliceSend("first");
	const m1Body = m1.body.slice();
	const m1Type = m1.message_type;
	const got1 = await bobDecrypt(m1Body, m1Type);
	const consumed = bob.count("prekeys") === 0 && bob.count("kyber_prekeys") === 0 && bob.count("sessions") === 1;

	// 2. "Restart": rebuild Bob purely from SQLite.
	bob = await ProtocolStore.load(db, sealer, "aci", bobPair, bobRegId);
	const m2 = await aliceSend("second, after restart");
	const got2 = await bobDecrypt(m2.body, m2.message_type);

	// 3. Bob replies from the rehydrated session; Alice decrypts.
	const reply = await sig.encryptMessage(enc.encode("reply"), addr(ALICE), addr(BOB), bob.sessions, bob.identityStore);
	await bob.saveSession(ALICE, 1);
	const gotReply = dec.decode(
		(await sig.decryptMessage(reply.body, reply.message_type, addr(BOB), addr(ALICE), alice.sessions, alice.identity, alice.preKeys, alice.signed, alice.kyber)).plaintext,
	);

	// 4. Another restart, then a normal (non-prekey) message.
	bob = await ProtocolStore.load(db, sealer, "aci", bobPair, bobRegId);
	const m3 = await aliceSend("third");
	const got3 = await bobDecrypt(m3.body, m3.message_type);

	// 5. Replaying the first message must fail after restarts.
	let replayError = "";
	try {
		await bobDecrypt(m1Body, m1Type);
	} catch (e) {
		replayError = String(e);
	}
	// signal-wasm reports every failure as "SignalError: Operation failed", so check behaviour:
	// the replay throws, and the session still works afterwards.
	const after = await aliceSend("after replay");
	const replayRejected = replayError !== "" && (await bobDecrypt(after.body, after.message_type)) === "after replay";

	// 6. Rows are sealed: a blob moved to another row must not open.
	const row = db.exec<{ record: ArrayBuffer }>("SELECT record FROM sessions LIMIT 1")[0];
	let wrongRowRejected = false;
	try {
		await sealer.open("sessions|aci|someone-else.1", new Uint8Array(row!.record));
	} catch {
		wrongRowRejected = true;
	}

	const results = {
		keysGenerated: keysBefore.preKeys === 1 && keysBefore.kyber === 1,
		firstContact: got1 === "first",
		oneTimeKeysTombstoned: consumed,
		afterRestart: got2 === "second, after restart",
		replyFromRestoredSession: gotReply === "reply",
		ratchetAfterSecondRestart: got3 === "third" && m3.message_type === sig.message_type_signal(),
		replayRejected,
		wrongRowRejected,
	};
	return { ok: Object.values(results).every(Boolean), ...results, replayError };
}
