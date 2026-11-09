// Receive-path self-test in a throwaway SignalAccount instance: an in-memory "Alice"
// sends a first-contact PreKey envelope (padded Content with a group DataMessage and a
// SenderKeyDistributionMessage) to a durable "Bob", then "reinstalls" (new identity key) and
// writes again, which must decrypt and be reported as a changed identity. Then a message Bob can't
// decrypt must yield a retry request whose ratchet key matches Alice's session, and that request must
// parse when it comes back as PlaintextContent. Sealed sender is checked with a certificate from a
// test trust root (Signal's real ones are issued only by its servers): a message we seal unseals to
// the same inner message, which decrypts, and Signal's own roots reject that certificate.

import type { SqlDatabase } from "../sql.js";
import { fromBase64, toBase64 } from "../util/bytes.js";
import type { Sealer } from "../util/sealer.js";
import { IdentityLog, createIdentitySchema } from "../protocol/identities.js";
import { MessageStore, createMessageSchema } from "../protocol/messages.js";
import { Decoded, encode } from "../protocol/proto.js";
import { receiveEnvelope } from "../protocol/receiver.js";
import { createRetrySchema, DecryptFailure, decryptionErrorFor, parseDecryptionError, plaintextContent, SendLog } from "../protocol/retry.js";
import { attachmentPointer, decryptAttachment, encryptAttachment, expandLongText, LONG_TEXT_TYPE, paddedSize, truncateUtf8 } from "../protocol/attachments.js";
import { checkMentions, defuseMentionTokens, extractMentions, parseContent, parseMentions, showMentions, validMentions } from "../protocol/content.js";
import { accessKey, CONTENT_HINT, libsignalExtra, unseal } from "../protocol/sealed.js";
import { dataMessage as encodeDataMessage, identityFor, quoteMessage, reactionMessage, type SendContext } from "../protocol/sender.js";
import { ProtocolStore, createStoreSchema } from "../protocol/store.js";
import { ChatTimers, createTimerSchema } from "../protocol/timers.js";
import { createSenderKeySchema, SenderKeyShares } from "../protocol/sender-keys.js";
import { Counters, createCounterSchema, describeCounters } from "../counters.js";
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
	// Sender-key group send (src/signal/sender-keys.ts): Alice's sender-key message, sealed for Bob in a
	// multi-recipient message from her signal-wasm session record, opened as the server and Bob would,
	// decrypts with the distribution message she shares.
	const multi = { roundTrip: false, decrypts: false, error: undefined as string | undefined };
	try {
		const aliceSenderKeys = new sig.WasmInMemSenderKeyStore();
		const distribution = crypto.randomUUID();
		const shared = await sig.createSenderKeyDistribution(addr(ALICE), distribution, aliceSenderKeys);
		const groupContent = encode([[1, encode([[1, "to the group"], [7, sentAt5 + 5]])]]);
		const skm = await sig.encryptGroupMessage(addr(ALICE), distribution, pad(groupContent), aliceSenderKeys);
		const session = (await alice2.sessions.export_session(addr(BOB)))!;
		const mrm = x.seal_multi_recipient([BOB], new Uint32Array([1]), bobPublic, session, new Uint32Array([session.length]), alice2Pair, certificate, skm, CONTENT_HINT.RESENDABLE, sealedGroupId);
		const um = x.unseal_multi_recipient_for_test(mrm, BOB, 1, bobPair, sentAt5, rootPub);
		multi.roundTrip = um.sender_aci === ALICE && um.msg_type === 7 && toBase64(um.contents) === toBase64(skm) && !!um.group_id && toBase64(um.group_id) === toBase64(sealedGroupId);
		const bobSenderKeys = new sig.WasmInMemSenderKeyStore();
		await sig.processSenderKeyDistribution(addr(ALICE), shared, bobSenderKeys);
		const opened = await sig.decryptGroupMessage(addr(ALICE), um.contents, bobSenderKeys);
		um.free();
		const end = opened.lastIndexOf(0x80);
		multi.decrypts = toBase64(opened.subarray(0, end)) === toBase64(groupContent);
	} catch (e) {
		multi.error = String(e);
	}
	createSenderKeySchema(db);
	const shares = new SenderKeyShares(db);
	shares.put("g1", { distributionId: "d", createdAt: 1, devices: [{ aci: ALICE, device: 1, registrationId: 5 }, { aci: ALICE, device: 2, registrationId: 6 }] });
	shares.forgetDevice(ALICE, 2);
	const forgetsDevice = shares.get("g1")?.devices.length === 1 && shares.get("g1")?.devices[0]?.device === 1;

	// zkgroup's known-answer vector (rust/zkgroup/src/api/profiles/profile_key.rs access_key_kat).
	const hex = (h: string) => new Uint8Array(h.match(/../g)!.map((b) => parseInt(b, 16)));
	const accessKeyKat = toBase64(accessKey(hex("b95042a2c2d9e5b3bb09300ee408a172facd96e91b504e043a5a023dc4cff359"))) === toBase64(hex("24fb96d4a5e333e9d4451205b9e2faed"));

	// Outgoing attachments (src/signal/attachments.ts): our encryption opens with the receive path's
	// decryption, and the pointer we write parses back to the same fields.
	const file = crypto.getRandomValues(new Uint8Array(3000));
	const encrypted = await encryptAttachment(file);
	const opened = await decryptAttachment(encrypted.blob, encrypted.keys, encrypted.digest, file.length);
	const attachmentRoundTrip = toBase64(opened) === toBase64(file) && encrypted.blob.length === 16 + (Math.floor(paddedSize(file.length) / 16) + 1) * 16 + 32;
	const uploaded = { cdnNumber: 3, cdnKey: "testkey123", key: toBase64(encrypted.keys), digest: toBase64(encrypted.digest), size: file.length, uploadTimestamp: sentAt };
	const parsedPointer = parseContent(encode([[1, encode([[1, "see file"], [2, attachmentPointer(uploaded, { contentType: "image/png", fileName: "a.png", caption: "hi" })], [7, sentAt]])]]), ALICE, 1, BOB).records[0]?.attachments?.[0];
	const pointerRoundTrip =
		parsedPointer?.contentType === "image/png" &&
		parsedPointer.fileName === "a.png" &&
		parsedPointer.caption === "hi" &&
		parsedPointer.size === file.length &&
		parsedPointer.pointer?.cdnNumber === 3 &&
		parsedPointer.pointer.cdnKey === "testkey123" &&
		parsedPointer.pointer.key === uploaded.key &&
		parsedPointer.pointer.digest === uploaded.digest;
	const longText = "æ".repeat(1001); // 2002 bytes
	const cut = truncateUtf8(longText, 2000);
	const truncatesOnCharBoundary = cut.length === 1000 && new TextEncoder().encode(cut).length === 2000 && truncateUtf8("short", 2000) === "short";

	// Disappearing-message timers (src/signal/timers.ts): learned from plain messages and timer
	// updates, not reactions; Desktop's version rules; and what we write when sending.
	createTimerSchema(db);
	const seenIn = (dm: Uint8Array) => parseContent(encode([[1, dm]]), ALICE, 1, BOB).timers;
	const t1 = seenIn(encode([[1, "hi"], [5, 3600], [7, sentAt], [23, 3]]));
	const t2 = seenIn(encode([[4, 2], [5, 86400], [7, sentAt + 1], [23, 4]])); // timer update, no body
	const tSticker = seenIn(encode([[7, sentAt + 3], [5, 600], [23, 5], [11, encode([[1, new Uint8Array(16)], [3, 1]])]]));
	const t3 = seenIn(encode([[7, sentAt + 2], [16, encode([[1, "👍"], [5, sentAt]])]])); // reaction
	const timerParse = t1[0]?.conversation === `aci:${ALICE}` && t1[0].expireTimer === 3600 && t1[0].version === 3 && t2[0]?.expireTimer === 86400 && t2[0].version === 4 && t3.length === 0 && tSticker[0]?.expireTimer === 600;
	const timers = new ChatTimers(db);
	const c = `aci:${ALICE}`;
	timers.apply({ conversation: c, expireTimer: 3600, version: 3 });
	const ignoresOlder = !timers.apply({ conversation: c, expireTimer: 0, version: 2 });
	const ignoresZero = !timers.apply({ conversation: c, expireTimer: 0, version: 0 });
	const ignoresLegacy = !timers.apply({ conversation: c, expireTimer: 0 });
	const keptTimer = timers.get(c)?.expireTimer === 3600 && timers.get(c)?.version === 3;
	const newerTurnsOff = timers.apply({ conversation: c, expireTimer: 0, version: 4 }) && timers.get(c)?.expireTimer === 0;
	timers.apply({ conversation: "group:abc", expireTimer: 600 });
	const legacy = "aci:33333333-3333-4333-8333-333333333333";
	timers.apply({ conversation: legacy, expireTimer: 60 }); // learned only from a version-less message
	const ignoresUnknownChat = !timers.apply({ conversation: "unknown", expireTimer: 60, version: 1 });
	const unknownSend = timers.forSend(`aci:${BOB}`);
	const legacySend = timers.forSend(legacy);
	const sendRules =
		unknownSend.version === 0 &&
		unknownSend.expireTimer === undefined &&
		legacySend.expireTimer === 60 &&
		legacySend.version === 0 &&
		ignoresUnknownChat &&
		timers.forSend(c).version === 4 &&
		timers.forSend("group:abc").expireTimer === 600 &&
		timers.forSend("group:abc", 60).expireTimer === 60;
	const written = new Decoded(encodeDataMessage("x", sentAt, undefined, undefined, [], { version: 0 }));
	const writesZeroVersion = written.uint(23) === 0 && written.uint(5) === undefined;
	const timerRules = ignoresOlder && ignoresZero && ignoresLegacy && keptTimer && newerTurnsOff && sendRules && writesZeroVersion;

	// Long text received (Signal sends the whole text as an attachment; the body holds only its start).
	const fullText = "x".repeat(2500);
	const pointer = { cdnNumber: 3, cdnKey: "k", key: toBase64(new Uint8Array(64)) };
	const longRecords = [
		{ kind: "message" as const, conversation: `aci:${ALICE}`, author: ALICE, authorDevice: 1, outgoing: false, sentAt, body: fullText.slice(0, 2000), attachments: [{ contentType: LONG_TEXT_TYPE, size: 2500, pointer }, { contentType: "image/png", pointer }] },
		{ kind: "message" as const, conversation: `aci:${ALICE}`, author: ALICE, authorDevice: 1, outgoing: false, sentAt: sentAt + 1, body: "short", attachments: [{ contentType: LONG_TEXT_TYPE, size: 2500, pointer }] },
	];
	let fetches = 0;
	const expansion = await expandLongText(longRecords, 64 * 1024, async () => {
		if (fetches++ === 1) throw new Error("cdn down");
		return new TextEncoder().encode(fullText);
	});
	const longTextExpanded =
		expansion.expanded === 1 &&
		expansion.failed === 1 &&
		longRecords[0]!.body === fullText &&
		longRecords[0]!.attachments?.length === 1 &&
		longRecords[0]!.attachments[0]!.contentType === "image/png" &&
		longRecords[1]!.body === "short" &&
		longRecords[1]!.attachments?.[0]?.contentType === LONG_TEXT_TYPE;

	// The stored copy is replaced in place once the full text is in (MessageStore.replace).
	const firstStored = (await messages.latest(50)).find((m) => m.body === "hello group");
	const { id: _id, receivedAt: _r, ...firstRecord } = firstStored!;
	const replaced = await messages.replace({ ...firstRecord, body: "hello group (full text)" });
	const replacedInPlace = replaced && (await messages.get(firstStored!.id))?.body === "hello group (full text)";

	// Quoted replies and reactions: the target is found by (chat, sentAt), and what we send parses back.
	const target = await messages.findSent(firstRecord.conversation, firstRecord.sentAt);
	const findsTarget = target?.id === firstStored!.id && (await messages.findSent(firstRecord.conversation, firstRecord.sentAt + 12345)) === undefined && (await messages.findSent("aci:nobody", firstRecord.sentAt)) === undefined;
	const reply = parseContent(encode([[1, encodeDataMessage("agreed", sentAt + 5, undefined, undefined, [], {}, { quote: quoteMessage(sentAt, ALICE, "hello") })]]), ALICE, 1, BOB).records[0];
	const react = parseContent(encode([[1, encodeDataMessage(undefined, sentAt + 6, undefined, undefined, [], {}, { reaction: reactionMessage("👍", ALICE, sentAt) })]]), ALICE, 1, BOB).records[0];
	const unreact = parseContent(encode([[1, encodeDataMessage(undefined, sentAt + 7, undefined, undefined, [], {}, { reaction: reactionMessage("👍", ALICE, sentAt, true) })]]), ALICE, 1, BOB).records[0];
	// Mentions: "@[aci:…]" tokens → placeholders + BodyRanges (UTF-16 indices, so the emoji counts 2), parsed back and shown.
	const withMentions = extractMentions(`🎉 @[aci:${ALICE}] and @[aci:${BOB.toUpperCase()}], look`);
	const mentioned = parseContent(
		encode([[1, encodeDataMessage(withMentions.body, sentAt + 8, undefined, undefined, [], {}, { mentions: withMentions.mentions, quote: quoteMessage(sentAt, ALICE, withMentions.body, withMentions.mentions) })]]),
		ALICE,
		1,
		BOB,
	).records[0];
	const label = (aci: string) => (aci === ALICE ? "Alice" : aci === BOB ? "me" : "?");
	const refuses = (f: () => void) => {
		try {
			f();
			return false;
		} catch {
			return true;
		}
	};
	const mentionsRoundTrip =
		withMentions.body === "🎉 \uFFFC and \uFFFC, look" &&
		withMentions.mentions[0]?.start === 3 &&
		withMentions.mentions[1]?.aci === BOB &&
		mentioned?.mentions?.length === 2 &&
		showMentions(mentioned.body ?? "", mentioned.mentions, label) === "🎉 @Alice and @me, look" &&
		showMentions(mentioned.quote?.text ?? "", mentioned.quote?.mentions, label) === "🎉 @Alice and @me, look" &&
		showMentions("short", [{ start: 9, length: 1, aci: ALICE }], label) === "short" && // out of range: left alone
		showMentions("a\uFFFC", [{ start: 0, length: 2, aci: BOB }, { start: 1, length: 1, aci: ALICE }], label) === "a@Alice" && // wider than the placeholder: left alone
		showMentions("a\uFFFCb", [{ start: 1, length: 1, aci: ALICE }, { start: 1, length: 1, aci: BOB }], label) === "a@Aliceb" && // same placeholder twice: shown once
		showMentions("hi you", [{ start: 3, length: 3, aci: BOB }], label) === "hi you" && // not on a placeholder: left alone
		parseMentions([encode([[1, 0], [2, 1], [3, "PNI:" + ALICE]]), encode([[1, 0], [2, 1], [3, ALICE.toUpperCase()]])]).map((m) => m.aci).join() === ALICE && // only ACIs
		extractMentions("no mentions @[aci:nope]").mentions.length === 0 &&
		validMentions("a\uFFFC", [{ start: 1, length: 1, aci: ALICE }, { start: 1, length: 1, aci: BOB }]).length === 1 && // quoted back once
		defuseMentionTokens(`typed @[aci:${ALICE}]`) === `typed @(aci:${ALICE})` &&
		extractMentions(defuseMentionTokens(`@[aci:${ALICE}]`)).mentions.length === 0 &&
		refuses(() => checkMentions(withMentions.mentions, undefined)) && // not in a 1:1 chat
		refuses(() => checkMentions(withMentions.mentions, [ALICE])) && // Bob isn't a member
		!refuses(() => checkMentions(withMentions.mentions, [ALICE, BOB])) &&
		!refuses(() => checkMentions([], undefined));
	const quotesAndReactions =
		findsTarget &&
		reply?.kind === "message" &&
		reply.body === "agreed" &&
		reply.quote?.id === sentAt &&
		reply.quote.author === ALICE &&
		reply.quote.text === "hello" &&
		react?.kind === "reaction" &&
		react.reaction?.emoji === "👍" &&
		react.reaction.remove === false &&
		react.reaction.targetAuthor === ALICE &&
		react.reaction.targetSentAt === sentAt &&
		unreact?.reaction?.remove === true;

	// Lasting counters (src/counters.ts): totals add up, first/last times kept, the summary names them.
	createCounterSchema(db);
	const counters = new Counters(db);
	counters.bump("send:sealed", 1, 1_000);
	counters.bump("send:sealed", 2, 5_000);
	counters.bump("send:authenticated", 0, 6_000); // zero doesn't create a row
	counters.error("routine", "x".repeat(400), 7_000);
	const lasting = counters.counters();
	const summary = describeCounters(lasting, counters.errors());
	const countersKept =
		lasting["send:sealed"]?.total === 3 &&
		lasting["send:sealed"].firstAt === 1_000 &&
		lasting["send:sealed"].lastAt === 5_000 &&
		!lasting["send:authenticated"] &&
		counters.errors().routine?.message.length === 300 &&
		summary.some((l) => l.startsWith("sends: sealed 3")) &&
		summary.some((l) => l.startsWith("last routine error"));

	// An identity key nobody recorded (sessions from before the identities table) comes from the session.
	let recovered: Uint8Array | undefined;
	const noRecord = { get: async () => undefined, save: async (_id: string, key: Uint8Array) => void (recovered = key) } as unknown as IdentityLog;
	const fromSession = await identityFor({ ourAci: BOB, ourDeviceId: 1, auth: "", store: bob, identities: noRecord } as SendContext, ALICE, [1]);
	const identityFromSession = !!fromSession && toBase64(fromSession) === toBase64(aliceKey2) && !!recovered && toBase64(recovered) === toBase64(aliceKey2);

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
		attachmentRoundTrip,
		pointerRoundTrip,
		truncatesOnCharBoundary,
		senderKeyMultiRecipient: multi.roundTrip,
		senderKeyDecrypts: multi.decrypts,
		senderKeyForgetsDevice: forgetsDevice,
		longTextExpanded,
		countersKept,
		identityFromSession,
		replacedInPlace,
		quotesAndReactions,
		mentionsRoundTrip,
		timerParse,
		timerRules,
	};
	const rows = db.exec<{ n: number }>("SELECT COUNT(*) AS n FROM messages")[0]?.n;
	return { ok: Object.values(results).every(Boolean), ...results, added, again, rows, ...(r2.status === "decrypted" ? {} : { secondResult: r2 }), ...(failureOther ? { failureOther } : {}), ...(sealed.error ? { sealedError: sealed.error } : {}), ...(multi.error ? { senderKeyError: multi.error } : {}) };
}
