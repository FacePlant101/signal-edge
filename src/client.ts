import { signalFetch } from "./net/http.js";
import { decryptProvisionEnvelope, encryptDeviceName, newProvisioningKeyPair } from "./protocol/crypto.js";
import { decodeProvisioningAddress, type ProvisionMessage } from "./protocol/proto.js";
import { CHAT_HOST, SignalSocket } from "./protocol/socket.js";
import { createMessageSchema, MessageStore, type StoredMessage } from "./protocol/messages.js";
import {
	createDirectorySchema,
	credentialForToday,
	Directory,
	fetchCredentials,
	fetchGroupState,
	GroupFetchError,
	groupIdFromMasterKey,
	type Contact,
	type Credential,
	type GroupRecord,
} from "./protocol/groups.js";
import { accessKey, CONTENT_HINT, libsignalExtra } from "./protocol/sealed.js";
import { readStorage } from "./protocol/storage-service.js";
import type { WsRequest } from "./protocol/proto.js";
import { receiveEnvelope, type Self } from "./protocol/receiver.js";
import { contentWithData, contentWithSentTranscript, dataMessage, sendToServiceId, type SendContext } from "./protocol/sender.js";
import { createStoreSchema, ProtocolStore, type OurIdentity, type UploadPreKey, type UploadSignedPreKey } from "./protocol/store.js";
import { signal } from "./protocol/wasm.js";
import { createIdentitySchema, IdentityLog } from "./protocol/identities.js";
import { decodeEnvelope, type MessageRecord } from "./protocol/content.js";
import {
	createRetrySchema,
	decryptionErrorFor,
	DecryptFailure,
	Limiter,
	nullMessageContent,
	parseDecryptionError,
	plaintextContent,
	pruneRetryState,
	SeenEnvelopes,
	SEND_LOG_MS,
	SendLog,
	sendLogCount,
	type FailedMessage,
} from "./protocol/retry.js";
import { downloadAttachment } from "./protocol/attachments.js";
import type { SqlDatabase } from "./sql.js";
import { blob } from "./sql.js";
import { dec, enc, fromBase64, randomBytes, toBase64 } from "./util/bytes.js";
import { Sealer } from "./util/sealer.js";

export type LinkState =
	| { state: "unlinked" }
	| { state: "waiting_for_scan"; url: string; since: number }
	| { state: "linking" }
	| { state: "linked"; aci: string; pni?: string; number?: string; deviceId: number; linkedAt: number }
	| { state: "error"; message: string; at: number };

/** Everything needed to act as this linked device. Stored AES-GCM encrypted under the storage key. */
type AccountSecrets = {
	aci: string;
	pni?: string;
	number?: string;
	deviceId: number;
	password: string;
	registrationId: number;
	pniRegistrationId?: number;
	aciIdentityKeyPair: string; // base64 libsignal IdentityKeyPair serialization
	pniIdentityKeyPair?: string;
	profileKey: string;
	masterKey?: string;
	accountEntropyPool?: string;
	mediaRootBackupKey?: string;
	ephemeralBackupKey?: string;
	authCredentialSalt?: string;
	readReceipts: boolean;
	/** Keys uploaded with the link request; moved into the protocol store tables, then dropped here. */
	signedPreKeys?: { aci: PreKeyRecord; pni?: PreKeyRecord };
	kyberLastResortPreKeys?: { aci: PreKeyRecord; pni?: PreKeyRecord };
	linkedAt: number;
};
type PreKeyRecord = { id: number; record: string };

type KeyCounts = { count: number; pqCount: number };
type KeyUpload = { preKeys?: UploadPreKey[]; pqPreKeys?: UploadSignedPreKey[]; signedPreKey?: UploadSignedPreKey; pqLastResortPreKey?: UploadSignedPreKey };
export type KeyRefreshResult = Partial<Record<OurIdentity, { server: KeyCounts; uploaded: string[]; removedOldKeys: number }>>;

const DEFAULT_DEVICE_NAME = "signal-edge";
const ADDRESS_TIMEOUT_MS = 15_000;

// Signal-Desktop AccountManager.preload.ts: batch size, refill thresholds, rotation age.
const PRE_KEY_BATCH = 100;
const PRE_KEY_MINIMUM = 10;
const PRE_KEY_MAX_COUNT = 200;
const ROTATION_AGE_MS = 1.5 * 24 * 3600 * 1000;
const REFRESH_INTERVAL_MS = 24 * 3600 * 1000;
const REFRESH_RETRY_MS = 10 * 60 * 1000;
/** Desktop sends longer text as an attachment (long-text), which we can't upload yet. */
const MAX_TEXT_BYTES = 2000;
/** Default limit for attachment downloads. */
const MAX_ATTACHMENT_BYTES = 25_000_000;

/** The alarm doubles as a watchdog: it reconnects the chat socket if it dropped. */
const WATCHDOG_MS = 60_000;
const RECONNECT_MS = 5_000;
/** Group state older than this is refetched before sending to the group. */
const GROUP_STALE_MS = 3600 * 1000;
// Retry requests (src/signal/retry.ts). Desktop's RETRY_LIMIT is 5 per message; the hourly caps are ours.
const RETRIES_PER_MESSAGE = 5;
const RETRIES_PER_DEVICE_HOUR = 20;
const RETRIES_PER_HOUR = 60;
const HOUR_MS = 3600 * 1000;
/** Refetch the sender certificate when it has less than this left. */
const SENDER_CERTIFICATE_MARGIN_MS = HOUR_MS;
/** Wait this long after a failed sender-certificate fetch before trying again. */
const SENDER_CERTIFICATE_RETRY_MS = 5 * 60 * 1000;

export type DirectorySync = { storageVersion: number; contacts: number; groups: number; fetched: number; errors: string[] };
/** A chat for list views: stored conversations plus known groups, with display names. */
export type Chat = { chat: string; name: string; kind: "direct" | "group" | "self"; messages: number; lastSentAt?: number; lastAuthor?: string; note?: string };
/** Group details without the master key. */
export type GroupInfo = Omit<GroupRecord, "masterKey" | "members"> & { members?: { aci: string; name?: string; admin: boolean }[] };

export type DirectSendResult = {
	timestamp: number;
	/** The recipient's devices that got it (absent for Note to Self). */
	recipientDevices?: number[];
	sealedSender?: boolean;
	/** Our other devices that got the sync transcript. */
	syncedDevices?: number[];
	/** Delivered, but the transcript to our own devices failed. */
	syncError?: string;
	/** Chats whose safety number changed during the send. */
	safetyNumberChanged?: string[];
};

export type GroupSendResult = {
	timestamp: number;
	members: number;
	delivered: number;
	/** How many of the delivered copies went sealed sender. */
	sealedSender: number;
	failed: { aci: string; error: string }[];
	syncedDevices?: number[];
	syncError?: string;
	safetyNumberChanged?: string[];
};

export type ReceiveState = {
	connected: boolean;
	connectedAt?: number;
	lastClose?: string;
	authFailed?: boolean;
	envelopes: number;
	stored: number;
	ignored: number;
	failed: number;
	kinds: Record<string, number>;
	lastEnvelopeAt?: number;
	queueEmptyAt?: number;
	lastError?: string;
	/** Kept apart from lastError so it doesn't hide the decrypt error that caused it. */
	lastRetryError?: string;
};

// Signal-Desktop ts/util/getCapabilities.std.ts, for a device linked with a phone number.
const CAPABILITIES = { attachmentBackfill: false, spqr: true, usernameChangeSyncMessage: true, optionalPhoneNumber: false };

export type SignalClientOptions = {
	/** Synchronous SQLite: Durable Object storage (`durableObjectSql`), node:sqlite, better-sqlite3. */
	db: SqlDatabase;
	/** 32 random bytes, base64: AES-256-GCM key for everything the client stores. */
	storageKey: string | undefined;
	/** Shown in the phone's list of linked devices. */
	deviceName?: string;
	/** Keeps background work alive after the current request (Workers: `ctx.waitUntil`). */
	waitUntil?: (p: Promise<unknown>) => void;
	/**
	 * Asks the host to call `maintain()` at `at` (or earlier, if already scheduled sooner).
	 * Durable Objects: an alarm (`durableObjectHost` does this). Elsewhere: a timer.
	 */
	scheduleMaintenance?: (at: number) => void | Promise<void>;
	/** Records newly stored from one incoming envelope (duplicates excluded). Errors are logged, not thrown. */
	onMessages?: (records: MessageRecord[], self: Self) => void | Promise<void>;
};

/** Tables the client owns (reset() empties them). */
export const SIGNAL_TABLES = [
	"kv",
	"failed_envelopes",
	"prekeys",
	"signed_prekeys",
	"kyber_prekeys",
	"kyber_usage",
	"sessions",
	"sender_keys",
	"key_counters",
	"messages",
	"groups",
	"contacts",
	"send_log",
	"seen_envelopes",
	"identities",
] as const;

/**
 * One Signal account, acting as a linked device: linking, the receive loop, sending (1:1, groups,
 * sealed sender), contacts and groups, attachments, retry requests and key maintenance. State lives in
 * `db`, sealed with `storageKey`. Keep one instance per account and database (in Workers, inside one
 * Durable Object) and call `maintain()` when asked to through `scheduleMaintenance`.
 */
export class SignalClient {
	readonly #db: SqlDatabase;
	readonly #opts: SignalClientOptions;
	#sealerPromise?: Promise<Sealer>;
	#link: LinkState = { state: "unlinked" };
	#socket?: SignalSocket;
	#stores?: Promise<Partial<Record<OurIdentity, ProtocolStore>>>;
	#refreshing?: Promise<KeyRefreshResult>;
	#chat?: SignalSocket;
	#connecting?: Promise<void>;
	/** Serializes everything that touches session state: receiving and sending. */
	#protocol: Promise<unknown> = Promise.resolve();
	#receive: ReceiveState = { connected: false, envelopes: 0, stored: 0, ignored: 0, failed: 0, kinds: {} };
	#syncing?: Promise<DirectorySync>;
	#groupRefreshes = new Map<string, Promise<GroupRecord>>();
	#retryLimits = new Limiter();
	/** Access keys (base64) the server refused, per ACI: sends to them stay authenticated until the key changes. */
	#refusedAccessKeys = new Map<string, Set<string>>();
	/** A sender-certificate fetch in flight, shared by concurrent sends. */
	#senderCertificateFetch?: Promise<SendContext["sealedSender"]>;
	/** The sender certificate in kv, parsed; `owner` is the "aci.deviceId" it was fetched for. */
	#senderCertificate?: { owner: string; certificate: Uint8Array; expiresAt: number };
	/** After a failed sender-certificate fetch, sends stay authenticated until then. */
	#senderCertificateRetryAt = 0;

	/** Creates the tables if needed and reads the link state. Synchronous; no network. */
	constructor(opts: SignalClientOptions) {
		this.#opts = opts;
		this.#db = opts.db;
		this.#createSchema();
		const meta = this.#get("account_meta");
		if (meta) this.#link = JSON.parse(dec.decode(meta));
		// A (re)started instance has no socket: let the watchdog connect right away.
		if (this.#link.state === "linked") this.#schedule(Date.now() + 1000);
	}

	#createSchema(): void {
		this.#db.exec("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)");
		this.#db.exec(
			"CREATE TABLE IF NOT EXISTS failed_envelopes (id INTEGER PRIMARY KEY AUTOINCREMENT, received_at INTEGER NOT NULL, error TEXT NOT NULL, envelope BLOB NOT NULL)",
		);
		createStoreSchema(this.#db);
		createMessageSchema(this.#db);
		createDirectorySchema(this.#db);
		createRetrySchema(this.#db);
		createIdentitySchema(this.#db);
	}

	status(): LinkState {
		return this.#link;
	}

	/** Our ACI, PNI and device id; undefined until linked. */
	self(): Self | undefined {
		const l = this.#link;
		return l.state === "linked" ? { aci: l.aci, pni: l.pni, deviceId: l.deviceId } : undefined;
	}

	/** Opens a provisioning socket and returns the sgnl:// URL to show as a QR code. */
	async startLink(): Promise<LinkState> {
		if (this.#link.state === "linked") return this.#link;
		if (this.#link.state === "waiting_for_scan" && this.#socket && !this.#socket.closed) return this.#link;
		await this.#sealer(); // fail before showing a QR if the secret is missing
		await this.#socket?.close().catch(() => {});

		const keys = newProvisioningKeyPair();
		let gotAddress!: (address: string) => void;
		const address = new Promise<string>((resolve) => (gotAddress = resolve));

		const socket = await SignalSocket.connect("/v1/websocket/provisioning/", {
			onRequest: async (req) => {
				if (req.verb === "PUT" && req.path === "/v1/address" && req.body) {
					gotAddress(decodeProvisioningAddress(req.body) ?? "");
					return 200;
				}
				if (req.verb === "PUT" && req.path === "/v1/message" && req.body) {
					const body = req.body;
					// Ack first, then link outside the socket callback.
					const linking = this.#finishLink(body, keys.privateKey);
					this.#opts.waitUntil?.(linking);
					return 200;
				}
				return 404;
			},
			onClose: (code, reason) => {
				if (this.#socket === socket) this.#socket = undefined;
				if (this.#link.state === "waiting_for_scan") {
					this.#setLink({ state: "error", message: `QR code expired (socket closed: ${code} ${reason}). Start again.`, at: Date.now() });
				}
			},
		});
		this.#socket = socket;

		const uuid = await Promise.race([
			address,
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Signal sent no provisioning address")), ADDRESS_TIMEOUT_MS)),
		]);
		// Signal-Desktop ts/util/signalRoutes.std.ts linkDeviceRoute; no "nopni" capability, so the
		// phone sends our number and PNI identity too.
		const params = new URLSearchParams({ uuid, pub_key: toBase64(keys.publicKey), capabilities: "" });
		this.#setLink({ state: "waiting_for_scan", url: `sgnl://linkdevice?${params}`, since: Date.now() }, false);
		return this.#link;
	}

	/**
	 * Forgets the linked account locally: closes the sockets and empties SIGNAL_TABLES. The device stays
	 * listed on the phone until removed there. Cancel the host's scheduled maintain() yourself.
	 */
	async reset(): Promise<LinkState> {
		await this.#socket?.close().catch(() => {});
		const chat = this.#chat;
		this.#chat = undefined;
		await chat?.close().catch(() => {});
		this.#db.transaction(() => {
			for (const t of SIGNAL_TABLES) this.#db.exec(`DELETE FROM ${t}`);
		});
		this.#createSchema();
		this.#stores = undefined;
		this.#refusedAccessKeys.clear();
		this.#senderCertificate = undefined;
		this.#senderCertificateFetch = undefined; // a fetch still in flight is for the forgotten account
		this.#senderCertificateRetryAt = 0;
		this.#receive = { connected: false, envelopes: 0, stored: 0, ignored: 0, failed: 0, kinds: {} };
		this.#link = { state: "unlinked" };
		return this.#link;
	}

	/**
	 * Signal-Desktop AccountManager.maybeUpdateKeys, for ACI and PNI: refills one-time
	 * prekeys when the server holds too few (or too many), rotates the signed and
	 * last-resort Kyber keys after 1.5 days, uploads with PUT /v2/keys, prunes old keys.
	 */
	refreshKeys(force = false): Promise<KeyRefreshResult> {
		this.#refreshing ??= this.#refreshKeys(force).finally(() => (this.#refreshing = undefined));
		return this.#refreshing;
	}

	/** Local key and session counts plus the server's prekey counts, per identity. */
	async keyStatus(): Promise<unknown> {
		const a = await this.#loadSecrets();
		const stores = await this.#loadStores();
		const out: Record<string, unknown> = {};
		for (const [ours, s] of Object.entries(stores) as [OurIdentity, ProtocolStore][]) {
			out[ours] = {
				server: await this.#keyCounts(a, ours),
				local: {
					preKeys: s.count("prekeys"),
					kyberOneTime: s.count("kyber_prekeys", "AND last_resort = 0"),
					kyberLastResort: s.count("kyber_prekeys", "AND last_resort = 1"),
					signedPreKeys: s.count("signed_prekeys"),
					sessions: s.count("sessions"),
					newestSignedPreKey: s.newestKey("signed"),
				},
			};
		}
		out.nextRefresh = this.#getNumber("next_key_refresh");
		return out;
	}

	// --- receiving ---

	receiveStatus(): ReceiveState & { failedStored: number; messages: number; sendLog: number } {
		const failedStored = this.#db.exec<{ n: number }>("SELECT COUNT(*) AS n FROM failed_envelopes")[0]?.n ?? 0;
		const messages = this.#db.exec<{ n: number }>("SELECT COUNT(*) AS n FROM messages")[0]?.n ?? 0;
		return { ...this.#receive, failedStored, messages, sendLog: sendLogCount(this.#db) };
	}

	async messages(limit = 20, conversation?: string): Promise<StoredMessage[]> {
		return (await this.messageStore()).latest(Math.min(Math.max(limit, 1), 200), conversation);
	}

	async conversations(): Promise<ReturnType<MessageStore["conversations"]>> {
		return (await this.messageStore()).conversations();
	}

	/** Connects now (also clears a credentials failure, e.g. after relinking). */
	async startReceiving(): Promise<ReceiveState> {
		this.#receive.authFailed = false;
		await this.#connectChat();
		return this.#receive;
	}

	/** Closes the chat socket; maintain() opens it again. */
	async stopReceiving(): Promise<void> {
		const chat = this.#chat;
		this.#chat = undefined;
		await chat?.close().catch(() => {});
	}

	/** Authenticated chat socket: Signal pushes PUT /api/v1/message envelopes over it. */
	#connectChat(): Promise<void> {
		if (this.#chat && !this.#chat.closed) return Promise.resolve();
		this.#connecting ??= (async () => {
			const a = await this.#loadSecrets();
			const stores = await this.#loadStores();
			const messages = await this.messageStore();
			const identities = await this.#identities();
			const self: Self = { aci: a.aci, pni: a.pni, deviceId: a.deviceId };
			const pairs: Partial<Record<OurIdentity, Uint8Array>> = { aci: fromBase64(a.aciIdentityKeyPair) };
			if (a.pniIdentityKeyPair) pairs.pni = fromBase64(a.pniIdentityKeyPair);
			try {
				// libsignal rust/net/src/chat.rs AuthenticatedChatHeaders: Basic auth + receive-stories.
				const chat = await SignalSocket.connect(
					"/v1/websocket/",
					{
						onRequest: (req) => this.#onChatRequest(req, self, stores, pairs, messages, identities),
						onClose: (code, reason) => {
							if (this.#chat === chat) this.#chat = undefined;
							this.#receive.connected = false;
							this.#receive.lastClose = `${new Date().toISOString()} ${code} ${reason}`;
							this.#schedule(Date.now() + RECONNECT_MS);
						},
					},
					{ Authorization: deviceAuth(a), "X-Signal-Receive-Stories": "false" },
				);
				this.#chat = chat;
				this.#receive.connected = true;
				this.#receive.connectedAt = Date.now();
			} catch (e) {
				this.#receive.lastError = `${new Date().toISOString()} connect: ${e}`;
				// 401/403 on the upgrade: the device was removed or the password is wrong. Retrying won't help.
				if (/HTTP 40[13]\b/.test(String(e))) this.#receive.authFailed = true;
				throw e;
			}
		})().finally(() => (this.#connecting = undefined));
		return this.#connecting;
	}

	async #onChatRequest(
		req: WsRequest,
		self: Self,
		stores: Partial<Record<OurIdentity, ProtocolStore>>,
		pairs: Partial<Record<OurIdentity, Uint8Array>>,
		messages: MessageStore,
		identities: IdentityLog,
	): Promise<number> {
		if (req.verb === "PUT" && req.path === "/api/v1/queue/empty") {
			this.#receive.queueEmptyAt = Date.now();
			return 200;
		}
		if (req.verb !== "PUT" || req.path !== "/api/v1/message") return 400;

		const body = req.body ?? new Uint8Array(0);
		this.#receive.envelopes++;
		this.#receive.lastEnvelopeAt = Date.now();
		// A redelivered envelope (e.g. the instance restarted before the ack) can't decrypt again: skip it.
		const seen = new SeenEnvelopes(this.#db);
		const guid = (() => {
			try {
				return decodeEnvelope(body).serverGuid;
			} catch {
				return undefined;
			}
		})();
		try {
			// Checked and recorded under the protocol lock: after a reconnect the server can redeliver an
			// envelope while the old socket's handler is still processing the first copy.
			const r = await this.#withProtocolLock(async () => {
				if (seen.has(guid)) return undefined;
				try {
					const r = await receiveEnvelope(body, self, stores, pairs, identities);
					if (r.status === "decrypted") seen.add(guid);
					return r;
				} catch (e) {
					// A redelivery would fail the same way and ask again: treat it as processed too. (Reprocessing
					// failed_envelopes after a fix would have to bypass this check.)
					seen.add(guid);
					throw e;
				}
			});
			if (!r) {
				this.#receive.ignored++;
				this.#count("ignored:already processed");
				return 200;
			}
			if (r.status === "ignored") {
				this.#receive.ignored++;
				this.#count(`ignored:${r.reason}`);
			} else {
				for (const k of r.parsed.kinds) this.#count(k);
				if (r.identityChanged) {
					this.#count("identity-change");
					await messages.add([identityChangeRecord(r.sender, r.senderDevice)], r.serverGuid, Date.now());
				}
				const added = await messages.add(r.parsed.records, r.serverGuid, Date.now());
				this.#receive.stored += added;
				if (r.parsed.decryptionError) {
					const request = r.parsed.decryptionError;
					void this.#answerRetryRequest(r.sender, r.senderDevice, request, stores, identities, messages).catch((e) => this.#retryError("answering retry request", e));
				}
				// A copy we already had (e.g. resent after a retry request) mustn't start another reply run.
				if (added) this.#notifyMessages(r.parsed.records, self);
				// Outside the protocol lock: fetching group state is network-only.
				for (const g of r.parsed.groups) void this.#noteGroup(g.masterKey, g.revision).catch((e) => console.error("group refresh failed", e));
			}
		} catch (e) {
			// Ack anyway, or Signal redelivers it forever; keep it sealed so it can be reprocessed after a fix,
			// and ask the sender for it again when we know who sent it.
			if (e instanceof DecryptFailure) {
				const failed = e.failed;
				void this.#requestResend(failed, stores, identities, messages).catch((err) => this.#retryError("sending retry request", err));
			}
			this.#receive.failed++;
			this.#receive.lastError = `${new Date().toISOString()} envelope: ${e}`;
			console.error("envelope failed", e);
			const sealed = await (await this.#sealer()).seal("failed_envelopes", body);
			this.#db.exec("INSERT INTO failed_envelopes (received_at, error, envelope) VALUES (?, ?, ?)", Date.now(), String(e).slice(0, 500), sealed);
		}
		return 200;
	}

	// --- retry requests (src/signal/retry.ts) ---

	/** We couldn't decrypt a message: ask its sender (all their devices; the request names the one that sent it) to resend. */
	async #requestResend(failed: FailedMessage, stores: Partial<Record<OurIdentity, ProtocolStore>>, identities: IdentityLog, messages: MessageStore): Promise<void> {
		if (failed.ours !== "aci") return this.#count("retry-request:skipped (to our PNI)");
		if (failed.timestamp === undefined) return this.#count("retry-request:skipped (no timestamp)");
		// Built first: a message we can't name for the sender shouldn't use up the limits.
		const request = plaintextContent(decryptionErrorFor(failed));
		const device = `${failed.sender}.${failed.device}`;
		const allowed = this.#retryLimits.allow([
			{ key: `out:${device}:${failed.timestamp}`, max: RETRIES_PER_MESSAGE, windowMs: SEND_LOG_MS },
			{ key: `out:${device}`, max: RETRIES_PER_DEVICE_HOUR, windowMs: HOUR_MS },
			{ key: "out", max: RETRIES_PER_HOUR, windowMs: HOUR_MS },
		]);
		if (!allowed) return this.#count("retry-request:skipped (rate limit)");
		const a = await this.#loadSecrets();
		// Sealed like Desktop's when we can (never to ourselves): the server needn't learn whose message failed.
		const senderKey = failed.sender !== a.aci ? await this.#accessKey(failed.sender) : undefined;
		const sealedSender = senderKey && (await this.#sealedSender(a));
		await this.#withProtocolLock(async () => {
			const ctx = sendContext(a, stores, identities, undefined, this.#sealing(sealedSender));
			await sendToServiceId(ctx, failed.sender, request, Date.now(), { plaintext: true, urgent: false, accessKey: senderKey, contentHint: CONTENT_HINT.DEFAULT, groupId: failed.groupId });
			// A key fetch during the send may have saved a changed identity: put the notice in the chat.
			await this.#recordIdentityChanges(ctx, messages);
		});
		this.#count("retry-request:sent");
	}

	/**
	 * A contact's device couldn't decrypt one of our messages. As Desktop does: archive our session with
	 * that device if it is still on the ratchet key they name, then resend the message from the send log,
	 * or send a null message so the next one starts a fresh session.
	 */
	async #answerRetryRequest(
		requester: string,
		requesterDevice: number,
		bytes: Uint8Array,
		stores: Partial<Record<OurIdentity, ProtocolStore>>,
		identities: IdentityLog,
		messages: MessageStore,
	): Promise<void> {
		const req = parseDecryptionError(bytes);
		this.#count("retry-request:received");
		const a = await this.#loadSecrets();
		// The request names the device that sent the message; our other devices (the phone) answer for theirs.
		if (req.timestamp === undefined) return this.#count("retry-request:ignored (no timestamp)");
		if (req.deviceId !== a.deviceId) return this.#count("retry-request:for another device");
		const key = `in:${requester}.${requesterDevice}`;
		const allowed = this.#retryLimits.allow([
			{ key: `${key}:${req.timestamp}`, max: RETRIES_PER_MESSAGE, windowMs: SEND_LOG_MS },
			{ key, max: RETRIES_PER_DEVICE_HOUR, windowMs: HOUR_MS },
			{ key: "in", max: RETRIES_PER_HOUR, windowMs: HOUR_MS },
		]);
		if (!allowed) return this.#count("retry-request:ignored (rate limit)");
		const sendLog = await this.#sendLog();
		const timestamp = req.timestamp;
		const logged = await sendLog.get(requester, timestamp);
		const content = logged?.content;
		// Sealing lookups (maybe a certificate fetch) only when something may be sent, and not to ourselves.
		const requesterKey = requester !== a.aci && (content || req.ratchetKey) ? await this.#accessKey(requester) : undefined;
		const sealedSender = requesterKey && (await this.#sealedSender(a));
		await this.#withProtocolLock(async () => {
			const sig = signal();
			const store = stores.aci!;
			let archived = false;
			if (req.ratchetKey) {
				const matches = await store.sessions.session_current_ratchet_key_matches(new sig.WasmProtocolAddress(requester, requesterDevice), req.ratchetKey).catch(() => false);
				if (matches) {
					await store.sessions.archive_session(new sig.WasmProtocolAddress(requester, requesterDevice));
					await store.saveSession(requester, requesterDevice);
					archived = true;
					this.#count("retry-request:session archived");
				}
			}
			const ctx = sendContext(a, stores, identities, undefined, this.#sealing(sealedSender));
			if (content) {
				await sendToServiceId(ctx, requester, content, timestamp, { accessKey: requesterKey, contentHint: CONTENT_HINT.RESENDABLE, groupId: logged?.groupId });
				this.#count("retry-request:resent");
			} else if (archived) {
				await sendToServiceId(ctx, requester, nullMessageContent(), Date.now(), { urgent: false, accessKey: requesterKey, contentHint: CONTENT_HINT.IMPLICIT });
				this.#count("retry-request:null message sent");
			} else {
				this.#count("retry-request:nothing to resend");
			}
			await this.#recordIdentityChanges(ctx, messages);
		});
	}

	#retryError(what: string, e: unknown): void {
		this.#count("retry-request:failed");
		this.#receive.lastRetryError = `${new Date().toISOString()} ${what}: ${e}`;
		console.error(what, e);
	}

	/**
	 * Note to Self that only our other devices get. Not stored and not kept in the send log, so it fits
	 * one-time codes that nothing reading the message history should see.
	 */
	async notifySelf(body: string): Promise<void> {
		const a = await this.#loadSecrets();
		const stores = await this.#loadStores();
		const identities = await this.#identities();
		await this.#withProtocolLock(async () => {
			const timestamp = Date.now();
			const ctx = sendContext(a, stores, identities);
			await sendToServiceId(ctx, a.aci, contentWithSentTranscript(a.aci, timestamp, dataMessage(body, timestamp), []), timestamp);
		});
	}

	// --- sending ---

	/**
	 * Sends a text message to `aci:<uuid>` (or a bare UUID), `"self"` (Note to Self) or `group:<base64 id>`,
	 * plus the sync transcript that makes it
	 * appear on our other devices. For Note to Self the transcript is the only copy, as in Desktop.
	 */
	async sendText(to: string, body: string): Promise<DirectSendResult | GroupSendResult> {
		if (!body.trim()) throw new Error("empty message");
		if (new TextEncoder().encode(body).length > MAX_TEXT_BYTES) throw new Error(`message longer than ${MAX_TEXT_BYTES} bytes (long text needs an attachment)`);
		if (to.startsWith("group:")) return this.#sendGroupText(to.slice(6), body);
		const a = await this.#loadSecrets();
		const target = to === "self" ? a.aci : to.replace(/^aci:/, "").toLowerCase();
		if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(target)) throw new Error("recipient must be an ACI (UUID) or \"self\"");
		const stores = await this.#loadStores();
		const messages = await this.messageStore();
		const identities = await this.#identities();
		const isSelf = target === a.aci;
		// Network and storage lookups before taking the lock.
		const key = isSelf ? undefined : await this.#accessKey(target);
		const sealedSender = key && (await this.#sealedSender(a));
		return this.#withProtocolLock(async () => {
			const timestamp = Date.now();
			const ctx = sendContext(a, stores, identities, await this.#sendLog(), this.#sealing(sealedSender));
			// Our profile key lets the recipient decrypt our name and avatar.
			const data = dataMessage(body, timestamp, isSelf ? undefined : fromBase64(a.profileKey));
			const result: DirectSendResult = { timestamp };
			if (!isSelf) {
				result.recipientDevices = await sendToServiceId(ctx, target, contentWithData(data), timestamp, { accessKey: key, contentHint: CONTENT_HINT.RESENDABLE });
				result.sealedSender = !!ctx.sealedTo?.includes(target);
				this.#count(result.sealedSender ? "send:sealed" : "send:authenticated");
			}
			try {
				result.syncedDevices = await sendToServiceId(ctx, a.aci, contentWithSentTranscript(target, timestamp, data, isSelf ? [] : [target], ctx.sealedTo), timestamp);
			} catch (e) {
				if (isSelf) throw e;
				result.syncError = String(e); // delivered, but our phone won't show it
			}
			await messages.add(
				[{ kind: "message", conversation: `aci:${target}`, author: a.aci, authorDevice: a.deviceId, outgoing: true, sentAt: timestamp, body }],
				`local-${timestamp}`,
				timestamp,
			);
			result.safetyNumberChanged = await this.#recordIdentityChanges(ctx, messages);
			return result;
		});
	}

	/**
	 * Group text, sent as one 1:1-encrypted copy per member (Desktop's non-sender-key path), then a
	 * sync transcript listing who got it. Member list and revision come from the groups server.
	 */
	async #sendGroupText(groupId: string, body: string): Promise<GroupSendResult> {
		const a = await this.#loadSecrets();
		const dir = await this.directory();
		let g = await dir.group(groupId);
		if (!g) throw new Error(`unknown group ${groupId}; run a directory sync or wait for a message from it`);
		if (!g.fetchedAt || !g.members || Date.now() - g.fetchedAt > GROUP_STALE_MS) g = await this.#refreshGroup(g);
		if (g.fetchError) throw new Error(`can't send to this group: ${g.fetchError}`);
		if (g.terminated) throw new Error("this group has been ended");
		const me = g.members?.find((m) => m.aci === a.aci);
		if (!me) throw new Error("this account is not a member of the group");
		if (g.announcementsOnly && !me.admin) throw new Error("only admins can send in this group");
		const group = g;
		const recipients = (group.members ?? []).map((m) => m.aci).filter((aci) => aci !== a.aci);
		const stores = await this.#loadStores();
		const messages = await this.messageStore();
		const identities = await this.#identities();
		const keys = new Map<string, Uint8Array | undefined>();
		// Group records are decrypted once here, not once per member whose key isn't in this group's state.
		const allGroups = await dir.groups();
		for (const m of group.members ?? []) if (m.aci !== a.aci) keys.set(m.aci, await this.#accessKey(m.aci, m.profileKey, allGroups));
		const sealedSender = [...keys.values()].some(Boolean) ? await this.#sealedSender(a) : undefined;
		const groupIdBytes = fromBase64(group.id);
		return this.#withProtocolLock(async () => {
			const timestamp = Date.now();
			const ctx = sendContext(a, stores, identities, await this.#sendLog(), this.#sealing(sealedSender));
			const data = dataMessage(body, timestamp, fromBase64(a.profileKey), { masterKey: fromBase64(group.masterKey), revision: group.revision ?? 0 });
			const content = contentWithData(data);
			const delivered: string[] = [];
			const failed: { aci: string; error: string }[] = [];
			for (const aci of recipients) {
				try {
					await sendToServiceId(ctx, aci, content, timestamp, { accessKey: keys.get(aci), contentHint: CONTENT_HINT.RESENDABLE, groupId: groupIdBytes });
					delivered.push(aci);
				} catch (e) {
					failed.push({ aci, error: String(e).slice(0, 200) });
				}
			}
			if (recipients.length && !delivered.length) throw new Error(`sending failed for every member, e.g. ${failed[0]?.error}`);
			const sealedCount = delivered.filter((aci) => ctx.sealedTo?.includes(aci)).length;
			this.#count("send:sealed", sealedCount);
			this.#count("send:authenticated", delivered.length - sealedCount);
			const result: GroupSendResult = {
				timestamp,
				members: recipients.length,
				delivered: delivered.length,
				sealedSender: sealedCount,
				failed,
			};
			try {
				result.syncedDevices = await sendToServiceId(ctx, a.aci, contentWithSentTranscript(undefined, timestamp, data, delivered, ctx.sealedTo), timestamp);
			} catch (e) {
				result.syncError = String(e);
			}
			await messages.add(
				[{ kind: "message", conversation: `group:${group.id}`, author: a.aci, authorDevice: a.deviceId, outgoing: true, sentAt: timestamp, body }],
				`local-${timestamp}`,
				timestamp,
			);
			result.safetyNumberChanged = await this.#recordIdentityChanges(ctx, messages);
			return result;
		});
	}

	/** Adds a "safety number changed" entry to each chat whose key changed during a send; returns their ids. */
	async #recordIdentityChanges(ctx: SendContext, messages: MessageStore): Promise<string[] | undefined> {
		if (!ctx.identityChanges?.length) return undefined;
		const now = Date.now();
		for (const id of ctx.identityChanges) await messages.add([identityChangeRecord(id, 0)], `identity-${id}-${now}`, now);
		this.#count("identity-change");
		return ctx.identityChanges.map((id) => `aci:${id}`);
	}

	// --- sealed sender ---

	/**
	 * Our sender certificate (GET /v1/certificate/delivery, without our phone number) and identity key,
	 * kept in memory and sealed in kv until an hour before it expires. Undefined if it can't be had:
	 * sends then stay authenticated.
	 */
	async #sealedSender(a: AccountSecrets): Promise<SendContext["sealedSender"]> {
		const identityKeyPair = fromBase64(a.aciIdentityKeyPair);
		const owner = senderCertificateOwner(a);
		let cached = this.#senderCertificate?.owner === owner ? this.#senderCertificate : undefined;
		if (!cached) {
			try {
				const blob = this.#get("sender_certificate");
				// The AAD names our ACI and device: a certificate fetched for another link doesn't open.
				const certificate = blob && (await (await this.#sealer()).open(`sender_certificate|${owner}`, blob));
				if (certificate) cached = this.#senderCertificate = { owner, certificate, expiresAt: libsignalExtra().sender_certificate_expiration(certificate) };
			} catch (e) {
				console.error("cached sender certificate unreadable; fetching a new one", e);
			}
		}
		const remaining = (cached?.expiresAt ?? 0) - Date.now();
		if (cached && remaining >= SENDER_CERTIFICATE_MARGIN_MS) return { certificate: cached.certificate, identityKeyPair };
		// Near expiry or missing: refetch, but keep using a still-valid one while fetches fail.
		const stillValid = cached && remaining > 60_000 ? { certificate: cached.certificate, identityKeyPair } : undefined;
		if (Date.now() < this.#senderCertificateRetryAt) {
			if (!stillValid) this.#count("sealed-sender:no certificate");
			return stillValid;
		}
		if (!this.#senderCertificateFetch) {
			// After a reset (pending no longer current) the result is for the forgotten account: don't keep it.
			const current = () => this.#senderCertificateFetch === pending;
			const pending: Promise<SendContext["sealedSender"]> = this.#fetchSenderCertificate(a)
				.then(async (certificate) => {
					if (current()) await this.#keepSenderCertificate(owner, certificate);
					return { certificate, identityKeyPair };
				})
				.catch((e) => {
					// Don't pay a failing fetch on every send.
					if (current()) this.#senderCertificateRetryAt = Date.now() + SENDER_CERTIFICATE_RETRY_MS;
					console.error("sender certificate fetch failed", e);
					return undefined;
				})
				.finally(() => {
					if (this.#senderCertificateFetch === pending) this.#senderCertificateFetch = undefined;
				});
			this.#senderCertificateFetch = pending;
		}
		const fetched = (await this.#senderCertificateFetch) ?? stillValid;
		if (!fetched) this.#count("sealed-sender:no certificate");
		return fetched;
	}

	/** GET /v1/certificate/delivery without our phone number. */
	async #fetchSenderCertificate(a: AccountSecrets): Promise<Uint8Array> {
		const res = await signalFetch(CHAT_HOST, "GET", "/v1/certificate/delivery?includeE164=false", { headers: { Authorization: deviceAuth(a) } });
		if (res.status !== 200) throw new Error(`GET /v1/certificate/delivery failed: HTTP ${res.status}`);
		const certificate = fromBase64((JSON.parse(dec.decode(res.body)) as { certificate: string }).certificate);
		libsignalExtra().sender_certificate_expiration(certificate); // throws on a certificate we can't parse
		return certificate;
	}

	/** Keeps a fetched sender certificate in memory and sealed in kv (AAD bound to `owner`). */
	async #keepSenderCertificate(owner: string, certificate: Uint8Array): Promise<void> {
		const expiresAt = libsignalExtra().sender_certificate_expiration(certificate);
		this.#put("sender_certificate", await (await this.#sealer()).seal(`sender_certificate|${owner}`, certificate));
		this.#senderCertificate = { owner, certificate, expiresAt };
	}

	/**
	 * Access key for sealed sends to `aci`, from `profileKey` (e.g. the member record of the group being
	 * sent to), else the profile keys in contacts and in shared groups' state, skipping one the server
	 * refused before. Undefined (send authenticated) when there is none or it can't be read.
	 * Pass `groups` (Directory.groups()) when looking up many members, so it is read once.
	 */
	async #accessKey(aci: string, profileKey?: string, groups?: GroupRecord[]): Promise<Uint8Array | undefined> {
		const refused = this.#refusedAccessKeys.get(aci);
		// One unreadable profile key mustn't hide the others.
		const usable = (p: string) => {
			try {
				const key = accessKey(fromBase64(p));
				return refused?.has(toBase64(key)) ? undefined : key;
			} catch (e) {
				console.error(`unusable profile key for ${aci}`, e);
				return undefined;
			}
		};
		const first = profileKey && usable(profileKey);
		if (first) return first;
		try {
			for (const p of await (await this.directory()).profileKeys(aci, groups)) {
				const key = p !== profileKey && usable(p);
				if (key) return key;
			}
		} catch (e) {
			console.error(`no access key for ${aci}`, e);
		}
		return undefined;
	}

	/** Sealed-sender part of a SendContext: remembers access keys the server refused, so later sends skip them. */
	#sealing(sealedSender: SendContext["sealedSender"]): Pick<SendContext, "sealedSender" | "onAccessKeyRefused"> {
		return {
			sealedSender,
			onAccessKeyRefused: (serviceId, key) => {
				let refused = this.#refusedAccessKeys.get(serviceId);
				if (!refused) this.#refusedAccessKeys.set(serviceId, (refused = new Set()));
				refused.add(toBase64(key));
				this.#count("sealed-sender:access key refused");
			},
		};
	}

	#identities(): Promise<IdentityLog> {
		return this.#sealer().then((s) => new IdentityLog(this.#db, s));
	}

	// --- groups and contacts ---

	/** Reads the group list and contacts from the storage service, then fetches every group's state. */
	syncDirectory(): Promise<DirectorySync> {
		this.#syncing ??= this.#syncDirectory().finally(() => (this.#syncing = undefined));
		return this.#syncing;
	}

	async #syncDirectory(): Promise<DirectorySync> {
		const a = await this.#loadSecrets();
		const dir = await this.directory();
		const snapshot = await readStorage(deviceAuth(a), this.#accountMasterKey(a));
		await dir.replaceContacts(snapshot.contacts);
		const known = new Map((await dir.groups()).map((g) => [g.id, g]));
		for (const sg of snapshot.groups) {
			const id = groupIdFromMasterKey(sg.masterKey);
			const g: GroupRecord = { ...(known.get(id) ?? { id, masterKey: toBase64(sg.masterKey) }), source: "storage", blocked: sg.blocked, archived: sg.archived };
			await dir.putGroup(g);
			known.set(id, g);
		}
		const errors: string[] = [];
		let fetched = 0;
		for (const g of known.values()) {
			try {
				const next = await this.#refreshGroup(g);
				if (next.fetchError) errors.push(`${g.id.slice(0, 8)}…: ${next.fetchError}`);
				else fetched++;
			} catch (e) {
				errors.push(`${g.id.slice(0, 8)}…: ${e}`);
			}
		}
		this.#putNumber("next_directory_sync", Date.now() + REFRESH_INTERVAL_MS);
		const result = { storageVersion: snapshot.version, contacts: snapshot.contacts.length, groups: known.size, fetched, errors };
		console.log("directory synced", JSON.stringify(result));
		return result;
	}

	/** Groups with names and members (named from contacts where known); no master keys. */
	async groups(): Promise<GroupInfo[]> {
		const dir = await this.directory();
		const names = await this.#names(dir);
		return (await dir.groups()).map((g) => groupInfo(g, names));
	}

	async group(id: string, refresh = false): Promise<GroupInfo | undefined> {
		const dir = await this.directory();
		let g = await dir.group(id.replace(/^group:/, ""));
		if (g && refresh) g = await this.#refreshGroup(g);
		return g && groupInfo(g, await this.#names(dir));
	}

	/** Contacts from the storage service, without profile keys. */
	async contacts(): Promise<Omit<Contact, "profileKey">[]> {
		return (await (await this.directory()).contacts()).map(({ profileKey: _p, ...c }) => c);
	}

	/** Conversations with stored messages plus every known group, newest first. */
	async chats(): Promise<Chat[]> {
		const a = await this.#loadSecrets();
		const dir = await this.directory();
		const names = await this.#names(dir);
		const groups = new Map((await dir.groups()).map((g) => [`group:${g.id}`, g]));
		const out: Chat[] = [];
		for (const c of (await this.messageStore()).conversations()) {
			const g = groups.get(c.conversation);
			groups.delete(c.conversation);
			const aci = c.conversation.startsWith("aci:") ? c.conversation.slice(4) : undefined;
			out.push({
				chat: c.conversation,
				name: g ? (g.title ?? "Unnamed group") : aci === a.aci ? "Note to Self" : ((aci && names.get(aci)) ?? c.conversation),
				kind: c.conversation.startsWith("group:") ? "group" : aci === a.aci ? "self" : "direct",
				messages: c.messages,
				lastSentAt: c.lastSentAt,
				lastAuthor: c.lastAuthor === a.aci ? "me" : (names.get(c.lastAuthor) ?? c.lastAuthor),
				note: g?.fetchError,
			});
		}
		for (const [chat, g] of groups) out.push({ chat, name: g.title ?? "Unnamed group", kind: "group", messages: 0, note: g.fetchError });
		return out;
	}

	// --- attachments (src/signal/attachments.ts) ---

	/** Downloads and decrypts attachment `index` of stored message `messageId` (the row id). */
	async attachment(messageId: number, index: number, maxBytes = MAX_ATTACHMENT_BYTES): Promise<{ contentType?: string; fileName?: string; data: Uint8Array }> {
		const m = await (await this.messageStore()).get(messageId);
		const a = m?.attachments?.[index];
		if (!a) throw new Error(`no attachment ${messageId}/${index}`);
		if (!a.pointer) throw new Error("this attachment was received before the Worker kept download keys, or has none");
		if (a.size !== undefined && a.size > maxBytes) throw new Error(`attachment is ${a.size} bytes; the limit is ${maxBytes}`);
		return { contentType: a.contentType, fileName: a.fileName, data: await downloadAttachment(a.pointer, a.size) };
	}

	#notifyMessages(records: MessageRecord[], self: Self): void {
		const hook = this.#opts.onMessages;
		if (!hook) return;
		try {
			void Promise.resolve(hook(records, self)).catch((e) => console.error("onMessages failed", e));
		} catch (e) {
			console.error("onMessages failed", e);
		}
	}

	/** ACI → display name, from storage-service contacts. */
	async names(): Promise<Record<string, string>> {
		return Object.fromEntries(await this.#names(await this.directory()));
	}

	async #names(dir: Directory): Promise<Map<string, string>> {
		return new Map((await dir.contacts()).filter((c) => c.name).map((c) => [c.aci, c.name!]));
	}

	/** Records a group seen in a message; fetches its state when it is new or at a newer revision. */
	async #noteGroup(masterKey: Uint8Array, revision: number): Promise<void> {
		const dir = await this.directory();
		const id = groupIdFromMasterKey(masterKey);
		let g = await dir.group(id);
		if (!g) {
			g = { id, masterKey: toBase64(masterKey), source: "message" };
			await dir.putGroup(g);
		}
		if (g.revision === undefined || g.revision < revision) await this.#refreshGroup(g);
	}

	/** Fetches one group's state from the groups server and stores it (one fetch per group at a time). */
	#refreshGroup(g: GroupRecord): Promise<GroupRecord> {
		let p = this.#groupRefreshes.get(g.id);
		if (!p) {
			p = (async () => {
				const dir = await this.directory();
				let state: Partial<GroupRecord>;
				try {
					state = { ...(await fetchGroupState(fromBase64(g.masterKey), await this.#groupCredential())), fetchError: undefined };
				} catch (e) {
					if (!(e instanceof GroupFetchError)) throw e;
					state = { fetchError: e.message, fetchedAt: Date.now() };
				}
				// Storage flags may have changed while we were fetching.
				const next: GroupRecord = { ...((await dir.group(g.id)) ?? g), ...state };
				await dir.putGroup(next);
				return next;
			})().finally(() => this.#groupRefreshes.delete(g.id));
			this.#groupRefreshes.set(g.id, p);
		}
		return p;
	}

	/** Today's group auth credential, fetching a week's worth when today's is missing. */
	async #groupCredential(): Promise<Credential> {
		const sealer = await this.#sealer();
		const blob = this.#get("group_credentials");
		let credentials: Credential[] = blob ? JSON.parse(dec.decode(await sealer.open("group_credentials", blob))) : [];
		let today = credentialForToday(credentials);
		if (!today) {
			const a = await this.#loadSecrets();
			credentials = await fetchCredentials(deviceAuth(a), a.aci, a.pni);
			this.#put("group_credentials", await sealer.seal("group_credentials", enc.encode(JSON.stringify(credentials))));
			today = credentialForToday(credentials);
			if (!today) throw new Error("the server sent no group credential for today");
		}
		return today;
	}

	#accountMasterKey(a: AccountSecrets): Uint8Array {
		if (a.masterKey) return fromBase64(a.masterKey);
		if (a.accountEntropyPool) return libsignalExtra().master_key_from_entropy_pool(a.accountEntropyPool);
		throw new Error("no master key or account entropy pool from linking");
	}

	/** Groups and contacts as stored (lower level than groups()/contacts(); includes keys). */
	directory(): Promise<Directory> {
		return this.#sealer().then((s) => new Directory(this.#db, s));
	}

	#withProtocolLock<T>(fn: () => Promise<T>): Promise<T> {
		const run = this.#protocol.then(fn, fn);
		this.#protocol = run.catch(() => {});
		return run;
	}

	#count(kind: string, n = 1): void {
		if (n) this.#receive.kinds[kind] = (this.#receive.kinds[kind] ?? 0) + n;
	}

	#sendLog(): Promise<SendLog> {
		return this.#sealer().then((s) => new SendLog(this.#db, s));
	}

	/** The message history (lower level than messages()/chats()). */
	messageStore(): Promise<MessageStore> {
		return this.#sealer().then((s) => new MessageStore(this.#db, s));
	}

	#schedule(at: number): void {
		const schedule = this.#opts.scheduleMaintenance;
		if (!schedule) return;
		try {
			void Promise.resolve(schedule(at)).catch((e) => console.error("scheduleMaintenance failed", e));
		} catch (e) {
			console.error("scheduleMaintenance failed", e);
		}
	}

	/**
	 * Watchdog and housekeeping: reconnects the chat socket, prunes retry state, refreshes prekeys and
	 * syncs contacts and groups when due. Returns when to call it next (undefined: not until relinked
	 * or startReceiving()). Call it from a Durable Object alarm or a timer.
	 */
	async maintain(): Promise<number | undefined> {
		if (this.#link.state !== "linked") return undefined;
		try {
			if (!this.#receive.authFailed) await this.#connectChat().catch((e) => console.error("chat connect failed", e));
			pruneRetryState(this.#db);
			if (Date.now() >= (this.#getNumber("next_key_refresh") ?? 0)) {
				await this.refreshKeys().catch((e) => {
					console.error("key refresh failed", e);
					this.#putNumber("next_key_refresh", Date.now() + REFRESH_RETRY_MS);
				});
			}
			if (Date.now() >= (this.#getNumber("next_directory_sync") ?? 0)) {
				await this.syncDirectory().catch((e) => {
					console.error("directory sync failed", e);
					this.#putNumber("next_directory_sync", Date.now() + REFRESH_RETRY_MS);
				});
			}
		} catch (e) {
			console.error("maintenance failed", e);
		}
		return this.#receive.authFailed ? undefined : Date.now() + WATCHDOG_MS;
	}

	async #refreshKeys(force: boolean): Promise<KeyRefreshResult> {
		const a = await this.#loadSecrets();
		const stores = await this.#loadStores();
		const result: KeyRefreshResult = {};
		for (const [ours, s] of Object.entries(stores) as [OurIdentity, ProtocolStore][]) {
			const server = await this.#keyCounts(a, ours);
			const upload: KeyUpload = {};
			if (force || server.count < PRE_KEY_MINIMUM || server.count > PRE_KEY_MAX_COUNT) upload.preKeys = await s.generatePreKeys(PRE_KEY_BATCH);
			if (force || server.pqCount < PRE_KEY_MINIMUM || server.pqCount > PRE_KEY_MAX_COUNT) upload.pqPreKeys = await s.generateKyberPreKeys(PRE_KEY_BATCH);
			const stale = (t: number | undefined) => force || t === undefined || Date.now() - t > ROTATION_AGE_MS;
			if (stale(s.newestKey("signed"))) upload.signedPreKey = await s.generateSignedPreKey();
			if (stale(s.newestKey("last_resort"))) upload.pqLastResortPreKey = (await s.generateKyberPreKeys(1, true))[0];

			const uploaded = Object.keys(upload);
			if (uploaded.length) {
				try {
					const res = await signalFetch(CHAT_HOST, "PUT", `/v2/keys?identity=${ours}`, { headers: { Authorization: deviceAuth(a) }, json: upload });
					if (res.status !== 200 && res.status !== 204) throw new Error(`PUT /v2/keys?identity=${ours} failed: HTTP ${res.status} ${dec.decode(res.body).slice(0, 300)}`);
				} catch (e) {
					// Never published, so nobody can encrypt to them: drop them rather than keep orphans.
					s.discardKeys({
						prekeys: upload.preKeys?.map((k) => k.keyId),
						kyber_prekeys: [...(upload.pqPreKeys ?? []), ...(upload.pqLastResortPreKey ? [upload.pqLastResortPreKey] : [])].map((k) => k.keyId),
						signed_prekeys: upload.signedPreKey && [upload.signedPreKey.keyId],
					});
					throw e;
				}
			}
			result[ours] = { server, uploaded, removedOldKeys: s.cleanupOldKeys() };
		}
		this.#putNumber("next_key_refresh", Date.now() + REFRESH_INTERVAL_MS);
		console.log("keys refreshed", JSON.stringify(result));
		return result;
	}

	async #keyCounts(a: AccountSecrets, ours: OurIdentity): Promise<KeyCounts> {
		const res = await signalFetch(CHAT_HOST, "GET", `/v2/keys?identity=${ours}`, { headers: { Authorization: deviceAuth(a) } });
		if (res.status !== 200) throw new Error(`GET /v2/keys?identity=${ours} failed: HTTP ${res.status}`);
		return JSON.parse(dec.decode(res.body)) as KeyCounts;
	}

	/** Protocol stores for ACI (and PNI if linked with a number), loaded once per DO instance. */
	#loadStores(): Promise<Partial<Record<OurIdentity, ProtocolStore>>> {
		this.#stores ??= (async () => {
			const a = await this.#loadSecrets();
			const sealer = await this.#sealer();
			const stores: Partial<Record<OurIdentity, ProtocolStore>> = {
				aci: await ProtocolStore.load(this.#db, sealer, "aci", fromBase64(a.aciIdentityKeyPair), a.registrationId),
			};
			if (a.pniIdentityKeyPair && a.pniRegistrationId !== undefined) {
				stores.pni = await ProtocolStore.load(this.#db, sealer, "pni", fromBase64(a.pniIdentityKeyPair), a.pniRegistrationId);
			}
			await this.#migrateLinkKeys(a, stores);
			return stores;
		})().catch((e) => {
			this.#stores = undefined;
			throw e;
		});
		return this.#stores;
	}

	/** Moves the keys uploaded while linking (phase 2 kept them in the secrets blob) into the store. */
	async #migrateLinkKeys(a: AccountSecrets, stores: Partial<Record<OurIdentity, ProtocolStore>>): Promise<void> {
		if (!a.signedPreKeys && !a.kyberLastResortPreKeys) return;
		for (const ours of ["aci", "pni"] as const) {
			const s = stores[ours];
			const signed = a.signedPreKeys?.[ours];
			const kyber = a.kyberLastResortPreKeys?.[ours];
			if (s && signed) await s.importKey("signed_prekeys", signed.id, fromBase64(signed.record), a.linkedAt);
			if (s && kyber) await s.importKey("kyber_prekeys", kyber.id, fromBase64(kyber.record), a.linkedAt);
		}
		const { signedPreKeys: _s, kyberLastResortPreKeys: _k, ...rest } = a;
		await this.#saveSecrets(rest);
	}

	/** Proves the stored credentials work: GET /v1/accounts/whoami as this device. */
	async whoami(): Promise<unknown> {
		const a = await this.#loadSecrets();
		const res = await signalFetch(CHAT_HOST, "GET", "/v1/accounts/whoami", { headers: { Authorization: deviceAuth(a) } });
		return { status: res.status, body: tryJson(res.body) };
	}

	async #finishLink(envelope: Uint8Array, provisioningPrivateKey: Uint8Array): Promise<void> {
		this.#setLink({ state: "linking" }, false);
		try {
			const msg = await decryptProvisionEnvelope(envelope, provisioningPrivateKey);
			await this.#socket?.close().catch(() => {});
			const secrets = await this.#register(msg);
			await this.#saveSecrets(secrets);
			this.#stores = undefined;
			this.#setLink({ state: "linked", aci: secrets.aci, pni: secrets.pni, number: secrets.number, deviceId: secrets.deviceId, linkedAt: secrets.linkedAt });
		} catch (e) {
			console.error("link failed", e);
			this.#setLink({ state: "error", message: String(e), at: Date.now() });
			return;
		}
		// Desktop uploads one-time prekeys right after linking; the watchdog does that (no refresh
		// has run yet, so it is due) and opens the chat socket, then keeps retrying both.
		this.#schedule(Date.now());
	}

	/** Signal-Desktop AccountManager #doCreateAccount (linked) + WebAPI linkDevice. */
	async #register(msg: ProvisionMessage): Promise<AccountSecrets> {
		const sig = signal();
		if (!msg.provisioningCode) throw new Error("provisioning message has no provisioningCode");
		if (!msg.aciIdentityKeyPrivate) throw new Error("provisioning message has no ACI identity key");
		if (!msg.profileKey?.length) throw new Error("provisioning message has no profile key");
		if (!msg.masterKey?.length && !msg.accountEntropyPool) throw new Error("provisioning message has neither masterKey nor accountEntropyPool");
		const aci = msg.aciBinary?.length ? sig.uuid_to_string(msg.aciBinary) : msg.aci;
		if (!aci) throw new Error("provisioning message has no ACI");
		const pni = msg.pniBinary?.length ? sig.uuid_to_string(msg.pniBinary) : msg.pni?.replace(/^PNI:/, "");
		const hasE164 = pni != null;
		if (hasE164 && (!msg.number || !msg.pniIdentityKeyPrivate)) throw new Error("provisioning message has a PNI but no number or PNI key");

		const aciPair = identityPair(msg.aciIdentityKeyPrivate, msg.aciIdentityKeyPublic);
		const pniPair = hasE164 ? identityPair(msg.pniIdentityKeyPrivate!, msg.pniIdentityKeyPublic) : undefined;

		// 16 random bytes, base64 without the "==" padding, as Desktop does.
		const password = toBase64(randomBytes(16)).slice(0, -2);
		const registrationId = sig.generateRegistrationId();
		const pniRegistrationId = hasE164 ? sig.generateRegistrationId() : undefined;

		const aciKeys = await lastResortKeys(aciPair);
		const pniKeys = pniPair ? await lastResortKeys(pniPair) : undefined;

		const name = toBase64(await encryptDeviceName(this.#opts.deviceName ?? DEFAULT_DEVICE_NAME, sig.WasmIdentityKeyPair.deserialize(aciPair).public_key.serialize()));
		const res = await signalFetch(CHAT_HOST, "PUT", "/v1/devices/link", {
			headers: { Authorization: basicAuth(aci, password) },
			json: {
				verificationCode: msg.provisioningCode,
				accountAttributes: { fetchesMessages: true, name, registrationId, pniRegistrationId, capabilities: CAPABILITIES },
				aciSignedPreKey: aciKeys.signed.upload,
				aciPqLastResortPreKey: aciKeys.kyber.upload,
				pniSignedPreKey: pniKeys?.signed.upload,
				pniPqLastResortPreKey: pniKeys?.kyber.upload,
			},
		});
		if (res.status !== 200) throw new Error(`PUT /v1/devices/link failed: HTTP ${res.status} ${dec.decode(res.body).slice(0, 300)}`);
		const linked = JSON.parse(dec.decode(res.body)) as { uuid: string; pni?: string; deviceId: number };
		if (linked.uuid !== aci) throw new Error(`server linked ${linked.uuid}, expected ${aci}`);

		return {
			aci,
			pni: linked.pni ?? pni,
			number: msg.number,
			deviceId: linked.deviceId,
			password,
			registrationId,
			pniRegistrationId,
			aciIdentityKeyPair: toBase64(aciPair),
			pniIdentityKeyPair: pniPair && toBase64(pniPair),
			profileKey: toBase64(msg.profileKey),
			masterKey: msg.masterKey && toBase64(msg.masterKey),
			accountEntropyPool: msg.accountEntropyPool,
			mediaRootBackupKey: msg.mediaRootBackupKey && toBase64(msg.mediaRootBackupKey),
			ephemeralBackupKey: msg.ephemeralBackupKey && toBase64(msg.ephemeralBackupKey),
			authCredentialSalt: msg.authCredentialSalt && toBase64(msg.authCredentialSalt),
			readReceipts: msg.readReceipts ?? false,
			signedPreKeys: { aci: aciKeys.signed.stored, pni: pniKeys?.signed.stored },
			kyberLastResortPreKeys: { aci: aciKeys.kyber.stored, pni: pniKeys?.kyber.stored },
			linkedAt: Date.now(),
		};
	}

	// --- storage ---

	#get(key: string): Uint8Array | undefined {
		const row = this.#db.exec<{ value: ArrayBuffer | Uint8Array }>("SELECT value FROM kv WHERE key = ?", key)[0];
		return row && blob(row.value);
	}

	#put(key: string, value: Uint8Array): void {
		this.#db.exec("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", key, value);
	}

	#getNumber(key: string): number | undefined {
		const v = this.#get(key);
		return v ? Number(dec.decode(v)) : undefined;
	}

	#putNumber(key: string, value: number): void {
		this.#put(key, enc.encode(String(value)));
	}

	#setLink(link: LinkState, persist = true): void {
		this.#link = link;
		// Transient states live in memory only; a restarted DO shows the last durable state.
		if (persist && (link.state === "linked" || link.state === "error")) this.#put("account_meta", enc.encode(JSON.stringify(link)));
	}

	#sealer(): Promise<Sealer> {
		this.#sealerPromise ??= Sealer.fromBase64(this.#opts.storageKey).catch((e) => {
			this.#sealerPromise = undefined;
			throw e;
		});
		return this.#sealerPromise;
	}

	async #saveSecrets(s: AccountSecrets): Promise<void> {
		this.#put("account_secrets", await (await this.#sealer()).seal("account_secrets", enc.encode(JSON.stringify(s))));
	}

	async #loadSecrets(): Promise<AccountSecrets> {
		const blob = this.#get("account_secrets");
		if (!blob) throw new Error("not linked");
		return JSON.parse(dec.decode(await (await this.#sealer()).open("account_secrets", blob)));
	}
}

/** Serialized libsignal IdentityKeyPair from a raw 32-byte private key, checked against the sent public key. */
function identityPair(privateKey: Uint8Array, expectedPublic?: Uint8Array): Uint8Array {
	const sig = signal();
	const pub = sig.WasmPrivateKey.deserialize(privateKey).getPublicKey();
	const pubBytes = pub.serialize();
	if (expectedPublic?.length && (expectedPublic.length !== pubBytes.length || expectedPublic.some((b, i) => b !== pubBytes[i]))) {
		throw new Error("provisioning message identity public key does not match its private key");
	}
	return new sig.WasmIdentityKeyPair(sig.WasmPublicKey.deserialize(pubBytes), sig.WasmPrivateKey.deserialize(privateKey)).serialize();
}

function randomKeyId(): number {
	return (new DataView(randomBytes(4).buffer).getUint32(0) & 0xffffff) || 1;
}

/** Signed prekey and last-resort Kyber prekey for one identity, in upload and storage forms. */
async function lastResortKeys(pair: Uint8Array) {
	const sig = signal();
	// wasm-bindgen may consume arguments, so every call gets a fresh deserialized pair.
	const spk = await sig.generateSignedPreKey(randomKeyId(), sig.WasmIdentityKeyPair.deserialize(pair), new sig.WasmInMemSignedPreKeyStore());
	const kpk = await sig.generateKyberPreKey(randomKeyId(), sig.WasmIdentityKeyPair.deserialize(pair), new sig.WasmInMemKyberPreKeyStore());
	return {
		signed: {
			upload: { keyId: spk.id, publicKey: toBase64(spk.public_key), signature: toBase64(spk.signature) },
			stored: { id: spk.id, record: toBase64(spk.record) },
		},
		kyber: {
			upload: { keyId: kpk.id, publicKey: toBase64(kpk.public_key), signature: toBase64(kpk.signature) },
			stored: { id: kpk.id, record: toBase64(kpk.record) },
		},
	};
}

function basicAuth(user: string, password: string): string {
	return `Basic ${btoa(`${user}:${password}`)}`;
}

/**
 * Context for sendToServiceId with our ACI store; pass `sendLog` for messages that may be resent,
 * and `sealing` (SignalAccount.#sealing) for sends that may go sealed sender.
 */
function sendContext(
	a: AccountSecrets,
	stores: Partial<Record<OurIdentity, ProtocolStore>>,
	identities: IdentityLog,
	sendLog?: SendLog,
	sealing?: Pick<SendContext, "sealedSender" | "onAccessKeyRefused">,
): SendContext {
	return { ourAci: a.aci, ourDeviceId: a.deviceId, auth: deviceAuth(a), store: stores.aci!, identities, sendLog, ...sealing };
}

/** Who a sender certificate names: "aci.deviceId" (its sender), bound into its kv AAD. */
function senderCertificateOwner(a: AccountSecrets): string {
	return `${a.aci}.${a.deviceId}`;
}

/** Credentials of this linked device: "aci.deviceId:password". */
function deviceAuth(a: AccountSecrets): string {
	return basicAuth(`${a.aci}.${a.deviceId}`, a.password);
}

function tryJson(body: Uint8Array): unknown {
	const text = dec.decode(body);
	try {
		return JSON.parse(text);
	} catch {
		return text.slice(0, 300);
	}
}

function groupInfo(g: GroupRecord, names: Map<string, string>): GroupInfo {
	const { masterKey: _m, members, ...rest } = g;
	// Field by field: member records also hold profile keys.
	return { ...rest, members: members?.map((m) => ({ aci: m.aci, admin: m.admin, name: names.get(m.aci) })) };
}

/** Chat entry for a contact's new identity key (Signal's "safety number changed"). */
function identityChangeRecord(serviceId: string, device: number): MessageRecord {
	const now = Date.now();
	return { kind: "identity-change", conversation: `aci:${serviceId}`, author: serviceId, authorDevice: device, outgoing: false, sentAt: now };
}
