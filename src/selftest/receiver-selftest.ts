// Receive-path self-test in a throwaway SignalAccount instance: an in-memory "Alice"
// sends a first-contact PreKey envelope (padded Content with a group DataMessage and a
// SenderKeyDistributionMessage) to a durable "Bob", then "reinstalls" (new identity key) and
// writes again, which must decrypt and be reported as a changed identity. Then a message Bob can't
// decrypt must yield a retry request whose ratchet key matches Alice's session, and that request must
// parse when it comes back as PlaintextContent. Sealed sender is checked with a certificate from a
// test trust root (Signal's real ones are issued only by its servers): a message we seal unseals to
// the same inner message, which decrypts, and Signal's own roots reject that certificate.

import { fromBase64, toBase64 } from "../util/bytes.js";
import type { SqlDatabase } from "../sql.js";
import type { Sealer } from "../util/sealer.js";
import { IdentityLog, createIdentitySchema } from "../protocol/identities.js";
import { MessageStore, createMessageSchema } from "../protocol/messages.js";
import { Decoded, encode } from "../protocol/proto.js";
import { receiveEnvelope } from "../protocol/receiver.js";
import { createRetrySchema, DecryptFailure, decryptionErrorFor, parseDecryptionError, plaintextContent, SendLog } from "../protocol/retry.js";
import { accessKey, CONTENT_HINT, libsignalExtra, unseal } from "../protocol/sealed.js";
import { ProtocolStore, createStoreSchema } from "../protocol/store.js";
import { signal } from "../protocol/wasm.js";

const ALICE = "11111111-1111-4111-8111-111111111111";
const BOB = "22222222-2222-4222-8222-222222222222";

/** Signal's padding: 0x80 then zeros up to a multiple of 160 bytes. */
function pad(b: Uint8Array): Uint8Array {
	const out = new Uint8Array(Math.ceil((b.length + 1) / 160) * 160);
	out.set(b);
	out[b.length] = 0x80;
	return out;
}

export async function receiverSelfTest(db: SqlDatabase, sealer: Sealer) {
	const sig = signal();
	createStoreSchema(db);
	createMessageSchema(db);
	createIdentitySchema(db);
	// send_log as the retry-request release created it (no group_id), so the migration is exercised too.
	db.exec("DROP TABLE IF EXISTS send_log"); // the instance's constructor already made the current one
	db.exec("CREATE TABLE send_log (recipient TEXT NOT NULL, timestamp INTEGER NOT NULL, sent_at INTEGER NOT NULL, content BLOB NOT NULL, PRIMARY KEY (recipient, timestamp))");
	createRetrySchema(db);
	const identities = new IdentityLog(db, sealer);

	const bobPriv = sig.WasmPrivateKey.generate();
	const bobPair = new sig.WasmIdentityKeyPair(bobPriv.getPublicKey(), sig.WasmPrivateKey.deserialize(bobPriv.serialize())).serialize();
	const bobRegId = sig.generateRegistrationId();
	const bob = await ProtocolStore.load(db, sealer, "aci", bobPair, bobRegId);
	const [opk] = await bob.generatePreKeys(1);
	const [kyber] = await bob.generateKyberPreKeys(1);
	const spk = await bob.generateSignedPreKey();

	const alicePriv = sig.WasmPrivateKey.generate();
	const alice = {
		identity: new sig.WasmInMemIdentityKeyStore(new sig.WasmIdentityKeyPair(alicePriv.getPublicKey(), sig.WasmPrivateKey.deserialize(alicePriv.serialize())), sig.generateRegistrationId()),
		sessions: new sig.WasmInMemSessionStore(),
		senderKeys: new sig.WasmInMemSenderKeyStore(),
	};
	const addr = (n: string) => new sig.WasmProtocolAddress(n, 1);
	await sig.processPreKeyBundle(
		addr(BOB), addr(ALICE), bobRegId, sig.WasmIdentityKeyPair.deserialize(bobPair).public_key,
		spk.keyId, sig.WasmPublicKey.deserialize(fromBase64(spk.publicKey)), fromBase64(spk.signature),
		opk!.keyId, fromBase64(opk!.publicKey), kyber!.keyId, fromBase64(kyber!.publicKey), fromBase64(kyber!.signature),
		alice.sessions, alice.identity,
	);

	// Content { dataMessage { body, timestamp, groupV2 { masterKey } }, senderKeyDistributionMessage }
	const masterKey = crypto.getRandomValues(new Uint8Array(32));
	const distributionId = crypto.randomUUID();
	const skdm = await sig.createSenderKeyDistribution(addr(ALICE), distributionId, alice.senderKeys);
	const sentAt = 1_790_000_000_000;
	const dataMessage = encode([[1, "hello group"], [7, sentAt], [15, encode([[1, masterKey], [2, 1]])]]);
	const content = encode([[1, dataMessage], [7, skdm]]);

	const ct = await sig.encryptMessage(pad(content), addr(BOB), addr(ALICE), alice.sessions, alice.identity);
	const serverGuid = crypto.randomUUID();
	const envelope = encode([
		[1, 3], // PREKEY_MESSAGE
		[11, ALICE],
		[7, 1],
		[13, BOB],
		[5, sentAt],
		[8, ct.body],
		[9, serverGuid],
		[10, sentAt + 50],
	]);

	const r = await receiveEnvelope(envelope, { aci: BOB, deviceId: 1 }, { aci: bob }, { aci: bobPair }, identities);
	if (r.status !== "decrypted") return { ok: false, result: r };

	const messages = new MessageStore(db, sealer);
	const added = await messages.add(r.parsed.records, r.serverGuid, Date.now());
	const again = await messages.add(r.parsed.records, r.serverGuid, Date.now()); // redelivery
	const [stored] = await messages.latest(5);
	const expectedGroup = `group:${toBase64(sig.WasmGroupMasterKey.from_bytes(masterKey).derive_identifier().serialize)}`;

	// Alice reinstalls: a new identity key and a new session, using Bob's signed and a fresh Kyber prekey.
	const alice2Priv = sig.WasmPrivateKey.generate();
	const alice2 = {
		identity: new sig.WasmInMemIdentityKeyStore(new sig.WasmIdentityKeyPair(alice2Priv.getPublicKey(), sig.WasmPrivateKey.deserialize(alice2Priv.serialize())), sig.generateRegistrationId()),
		sessions: new sig.WasmInMemSessionStore(),
	};
	const [kyber2] = await bob.generateKyberPreKeys(1);
	await sig.processPreKeyBundle(
		addr(BOB), addr(ALICE), bobRegId, sig.WasmIdentityKeyPair.deserialize(bobPair).public_key,
		spk.keyId, sig.WasmPublicKey.deserialize(fromBase64(spk.publicKey)), fromBase64(spk.signature),
		undefined, undefined, kyber2!.keyId, fromBase64(kyber2!.publicKey), fromBase64(kyber2!.signature),
		alice2.sessions, alice2.identity,
	);
	const sentAt2 = sentAt + 60_000;
	const ct2 = await sig.encryptMessage(pad(encode([[1, encode([[1, "after reinstall"], [7, sentAt2]])]])), addr(BOB), addr(ALICE), alice2.sessions, alice2.identity);
	const envelope2 = encode([[1, 3], [11, ALICE], [7, 1], [13, BOB], [5, sentAt2], [8, ct2.body], [9, crypto.randomUUID()], [10, sentAt2 + 50]]);
	const identitiesBefore = identities.count();
	// Control: without the identity check (so no reset), libsignal's cache still holds the old key.
	const noCheck = { check: async () => "same", save: async () => {} } as unknown as IdentityLog;
	let staleRejected = false;
	try {
		await receiveEnvelope(envelope2, { aci: BOB, deviceId: 1 }, { aci: bob }, { aci: bobPair }, noCheck);
	} catch {
		staleRejected = true;
	}
	let r2: Awaited<ReturnType<typeof receiveEnvelope>> | { status: "error"; error: string };
	try {
		r2 = await receiveEnvelope(envelope2, { aci: BOB, deviceId: 1 }, { aci: bob }, { aci: bobPair }, identities);
	} catch (e) {
		r2 = { status: "error", error: String(e) };
	}
	// Retry request: Alice's next message arrives with a broken MAC (last byte of the embedded SignalMessage).
	const sentAt3 = sentAt2 + 60_000;
	const ct3 = await sig.encryptMessage(pad(encode([[1, encode([[1, "garbled"], [7, sentAt3]])]])), addr(BOB), addr(ALICE), alice2.sessions, alice2.identity);
	const broken = ct3.body.slice();
	const inner = new Decoded(broken.subarray(1)).bytes(4)!; // a view into `broken`
	inner[inner.length - 1]! ^= 1;
	const envelope3 = encode([[1, 3], [11, ALICE], [7, 1], [13, BOB], [5, sentAt3], [8, broken], [9, crypto.randomUUID()], [10, sentAt3 + 50]]);
	let failure: DecryptFailure | undefined;
	let failureOther: unknown;
	try {
		await receiveEnvelope(envelope3, { aci: BOB, deviceId: 1 }, { aci: bob }, { aci: bobPair }, identities);
	} catch (e) {
		if (e instanceof DecryptFailure) failure = e;
		else failureOther = String(e);
	}
	const request = failure && parseDecryptionError(decryptionErrorFor(failure.failed));
	const ratchetMatches = !!request?.ratchetKey && (await alice2.sessions.session_current_ratchet_key_matches(addr(BOB), request.ratchetKey));
	// The request as it travels (PlaintextContent, envelope type 8), received from "Alice" by Bob's receiver.
	const envelope4 = failure && encode([[1, 8], [11, ALICE], [7, 1], [13, BOB], [5, sentAt3 + 1], [8, plaintextContent(decryptionErrorFor(failure.failed))], [9, crypto.randomUUID()], [10, sentAt3 + 60]]);
	const r4 = envelope4 ? await receiveEnvelope(envelope4, { aci: BOB, deviceId: 1 }, { aci: bob }, { aci: bobPair }, identities).catch((e) => ({ status: "error", error: String(e) }) as const) : undefined;
	const received = r4?.status === "decrypted" && r4.parsed.decryptionError ? parseDecryptionError(r4.parsed.decryptionError) : undefined;

	const sendLog = new SendLog(db, sealer);
	const loggedGroupId = crypto.getRandomValues(new Uint8Array(32));
	await sendLog.save(ALICE, sentAt, content, loggedGroupId);
	const logged = await sendLog.get(ALICE, sentAt);
	const resentCopy = await messages.add(r.parsed.records, crypto.randomUUID(), Date.now()); // same message, new server guid

	const alice2Pair = new sig.WasmIdentityKeyPair(alice2Priv.getPublicKey(), sig.WasmPrivateKey.deserialize(alice2Priv.serialize())).serialize();
	const aliceKey2 = sig.WasmIdentityKeyPair.deserialize(alice2Pair).public_key.serialize();

	// Sealed sender (src/signal/sender.ts sends this way): Alice's next message, sealed to Bob.
	const x = libsignalExtra();
	const rootPriv = sig.WasmPrivateKey.generate();
	const rootPub = rootPriv.getPublicKey().serialize();
	const sentAt5 = sentAt3 + 120_000;
	const certificate = x.test_sender_certificate(rootPriv.serialize(), ALICE, 1, aliceKey2, sentAt5 + 86_400_000);
	const ct5 = await sig.encryptMessage(pad(encode([[1, encode([[1, "sealed hello"], [7, sentAt5]])]])), addr(BOB), addr(ALICE), alice2.sessions, alice2.identity);
	const bobPublic = sig.WasmIdentityKeyPair.deserialize(bobPair).public_key.serialize();
	const sealedGroupId = crypto.getRandomValues(new Uint8Array(32));
	const sealed = { roundTrip: false, innerDecrypts: false, rejectedBySignalRoots: false, retryRequest: false, error: undefined as string | undefined };
	try {
		const sealedBody = x.seal(BOB, 1, bobPublic, alice2Pair, certificate, ct5.message_type, ct5.body, CONTENT_HINT.RESENDABLE, sealedGroupId);
		const u = x.unseal_for_test(sealedBody, bobPair, sentAt5, BOB, 1, rootPub);
		sealed.roundTrip =
			u.sender_aci === ALICE &&
			u.sender_device === 1 &&
			u.msg_type === ct5.message_type &&
			toBase64(u.contents) === toBase64(ct5.body) &&
			u.content_hint === CONTENT_HINT.RESENDABLE &&
			!!u.group_id &&
			toBase64(u.group_id) === toBase64(sealedGroupId);
		const inner = encode([[1, 3], [11, ALICE], [7, 1], [13, BOB], [5, sentAt5], [8, u.contents], [9, crypto.randomUUID()], [10, sentAt5 + 50]]);
		u.free();
		const r5 = await receiveEnvelope(inner, { aci: BOB, deviceId: 1 }, { aci: bob }, { aci: bobPair }, identities);
		sealed.innerDecrypts = r5.status === "decrypted" && r5.parsed.records[0]?.body === "sealed hello";
		try {
			unseal(sealedBody, bobPair, sentAt5, BOB, 1).free();
		} catch (e) {
			// Our own message from sealed/src/lib.rs, not any other failure.
			sealed.rejectedBySignalRoots = String(e).includes("certificate failed trust-root");
		}
		// A retry request sealed the way sender.ts sends it (inner type 8, PlaintextContent).
		if (failure) {
			const sealedRequest = x.seal(BOB, 1, bobPublic, alice2Pair, certificate, 8, plaintextContent(decryptionErrorFor(failure.failed)), CONTENT_HINT.DEFAULT, undefined);
			const ur = x.unseal_for_test(sealedRequest, bobPair, sentAt5, BOB, 1, rootPub);
			const innerType = ur.msg_type;
			const env = encode([[1, 8], [11, ALICE], [7, 1], [13, BOB], [5, sentAt5 + 1], [8, ur.contents], [9, crypto.randomUUID()], [10, sentAt5 + 60]]);
			ur.free();
			const rr = await receiveEnvelope(env, { aci: BOB, deviceId: 1 }, { aci: bob }, { aci: bobPair }, identities);
			sealed.retryRequest = innerType === 8 && rr.status === "decrypted" && parseDecryptionError(rr.parsed.decryptionError ?? new Uint8Array(0)).timestamp === sentAt3;
		}
	} catch (e) {
		sealed.error = String(e);
	}
	// zkgroup's known-answer vector (rust/zkgroup/src/api/profiles/profile_key.rs access_key_kat).
	const hex = (h: string) => new Uint8Array(h.match(/../g)!.map((b) => parseInt(b, 16)));
	const accessKeyKat = toBase64(accessKey(hex("b95042a2c2d9e5b3bb09300ee408a172facd96e91b504e043a5a023dc4cff359"))) === toBase64(hex("24fb96d4a5e333e9d4451205b9e2faed"));

	const results = {
		sender: r.sender === ALICE && r.senderDevice === 1,
		kinds: r.parsed.kinds.join(",") === "data,sender-key-distribution",
		body: stored?.body === "hello group" && stored.sentAt === sentAt,
		groupConversation: stored?.conversation === expectedGroup,
		senderKeyStored: db.exec<{ n: number }>("SELECT COUNT(*) AS n FROM sender_keys WHERE distribution_id = ?", distributionId)[0]?.n === 1,
		oneTimeKeysConsumed: bob.count("prekeys") === 0 && bob.count("kyber_prekeys") === 0,
		redeliveryIgnored: added === 1 && again === 0,
		firstIdentityRecorded: r.identityChanged === false && identitiesBefore === 1,
		staleKeyRejectedWithoutReset: staleRejected,
		changedIdentityDecrypts: r2.status === "decrypted" && r2.parsed.records[0]?.body === "after reinstall",
		changedIdentityReported: r2.status === "decrypted" && r2.identityChanged === true,
		newIdentityRecorded: (await identities.check(ALICE, aliceKey2)) === "same",
		undecryptableNamesSender: failure?.failed.sender === ALICE && failure.failed.device === 1 && failure.failed.timestamp === sentAt3,
		retryRequestRatchetKeyMatches: ratchetMatches && request?.timestamp === sentAt3 && request.deviceId === 1,
		retryRequestReceived: r4?.status === "decrypted" && r4.parsed.kinds.includes("decryption-error") && received?.timestamp === sentAt3 && received.deviceId === 1 && !!received.ratchetKey && !!request?.ratchetKey && toBase64(received.ratchetKey) === toBase64(request.ratchetKey),
		sendLogRoundTrip:
			!!logged && toBase64(logged.content) === toBase64(content) && !!logged.groupId && toBase64(logged.groupId) === toBase64(loggedGroupId) && (await sendLog.get(ALICE, sentAt + 1)) === undefined,
		resentCopyIgnored: resentCopy === 0,
		sealedRoundTrip: sealed.roundTrip,
		sealedInnerDecrypts: sealed.innerDecrypts,
		sealedRejectedBySignalRoots: sealed.rejectedBySignalRoots,
		sealedRetryRequest: sealed.retryRequest,
		accessKeyKat,
	};
	const rows = db.exec<{ n: number }>("SELECT COUNT(*) AS n FROM messages")[0]?.n;
	return { ok: Object.values(results).every(Boolean), ...results, added, again, rows, ...(r2.status === "decrypted" ? {} : { secondResult: r2 }), ...(failureOther ? { failureOther } : {}), ...(sealed.error ? { sealedError: sealed.error } : {}) };
}
