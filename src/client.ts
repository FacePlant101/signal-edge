import { signalFetch } from "./net/http.js";
import { decryptProvisionEnvelope, encryptDeviceName, newProvisioningKeyPair } from "./protocol/crypto.js";
import { decodeProvisioningAddress, type ProvisionMessage } from "./protocol/proto.js";
import { CHAT_HOST, SignalSocket } from "./protocol/socket.js";
import { createMessageSchema, MessageStore, type Conversation, type StoredMessage } from "./protocol/messages.js";
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
import { contentWithData, contentWithSentTranscript, dataMessage, quoteMessage, reactionMessage, sendToServiceId, type SendContext } from "./protocol/sender.js";
import { createStoreSchema, ProtocolStore, type OurIdentity, type UploadPreKey, type UploadSignedPreKey } from "./protocol/store.js";
import { signal } from "./protocol/wasm.js";
import { createIdentitySchema, IdentityLog } from "./protocol/identities.js";
import { ChatTimers, createTimerSchema, type Expiry } from "./protocol/timers.js";
import { createSenderKeySchema, SenderKeyShares, senderKeyUsable, sendWithSenderKey } from "./protocol/sender-keys.js";
import { ACI_PATTERN, checkMentions, decodeEnvelope, extractMentions, validMentions, type Attachment, type Mention, type MessageRecord, type ParsedContent, groupsNamed, keepGroups } from "./protocol/content.js";
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
import { attachmentPointer, downloadAttachment, expandLongText, LONG_TEXT_TYPE, truncateUtf8, uploadAttachment } from "./protocol/attachments.js";
import { Counters, createCounterSchema, type LastError, type LastingCounter } from "./counters.js";
import { blob, type SqlDatabase, type SqlValue } from "./sql.js";
import { dec, enc, fromBase64, randomBytes, toBase64 } from "./util/bytes.js";
import { Sealer } from "./util/sealer.js";
import {
	createVerificationSession,
	generateAccountEntropyPool,
	registerAccount,
	registrationRecoveryPassword,
	requestVerificationCode,
	submitCaptcha as submitCaptchaToSession,
	submitVerificationCode,
	type VerificationSession,
	type VerificationTransport,
} from "./protocol/registration.js";

export type LinkState =
	| { state: "unlinked" }
	| { state: "waiting_for_scan"; url: string; since: number }
	| { state: "linking" }
	/**
	 * Registering a new primary account (no phone app). `step`: "captcha" (solve one at
	 * signalcaptchas.org/registration/generate.html and pass its token), "request_code" (by SMS or
	 * voice), "enter_code". Times say when the server allows the next SMS, call or code attempt.
	 */
	| {
			state: "registering";
			number: string;
			step: "captcha" | "request_code" | "enter_code";
			nextSmsAt?: number;
			nextCallAt?: number;
			nextVerificationAttemptAt?: number;
	  }
	| {
			state: "linked";
			aci: string;
			pni?: string;
			/** The account's phone number. After a restart it is back once the sealed secrets have been read (started by the constructor). */
			number?: string;
			deviceId: number;
			linkedAt: number;
			/** Registered as this account's primary device (standalone, no phone app) rather than linked. */
			primary?: boolean;
	  }
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
	/** The account's primary device (registered here with a phone number), not a linked one. */
	primary?: boolean;
};
type PreKeyRecord = { id: number; record: string };
/** A registration in progress: the verification session for `number`, for the account generation it began in. */
type Registration = { number: string; session: VerificationSession; codeRequested: boolean; generation: number };

type KeyCounts = { count: number; pqCount: number };
type KeyUpload = { preKeys?: UploadPreKey[]; pqPreKeys?: UploadSignedPreKey[]; signedPreKey?: UploadSignedPreKey; pqLastResortPreKey?: UploadSignedPreKey };
export type KeyRefreshResult = Partial<Record<OurIdentity, { server: KeyCounts; uploaded: string[]; removedOldKeys: number }>>;

const DEFAULT_DEVICE_NAME = "signal-edge";
/** How long a primary account's "do we have linked devices" answer is trusted. */
const LINKED_DEVICES_CHECK_MS = 10 * 60 * 1000;
const ADDRESS_TIMEOUT_MS = 15_000;

// Signal-Desktop AccountManager.preload.ts: batch size, refill thresholds, rotation age.
const PRE_KEY_BATCH = 100;
const PRE_KEY_MINIMUM = 10;
const PRE_KEY_MAX_COUNT = 200;
const ROTATION_AGE_MS = 1.5 * 24 * 3600 * 1000;
const REFRESH_INTERVAL_MS = 24 * 3600 * 1000;
const REFRESH_RETRY_MS = 10 * 60 * 1000;
/** Text beyond this goes out as a long-text attachment, as Desktop does (its limit is 2 KiB). */
const MAX_TEXT_BYTES = 2000;
/** Desktop MAX_BODY_ATTACHMENT_BYTE_LENGTH: the longest text a long-text attachment may hold. */
const MAX_LONG_TEXT_BYTES = 64 * 1024;
const MAX_SEND_FILES = 5;
/** How long a received message waits for its long-text attachment before it is stored without it. */
const LONG_TEXT_TIMEOUT_MS = 8_000;
/** Default for SignalClientOptions.maxAttachmentBytes. */
const DEFAULT_MAX_ATTACHMENT_BYTES = 25_000_000;

/** The alarm doubles as a watchdog: it reconnects the chat socket if it dropped. */
const WATCHDOG_MS = 60_000;
/** Undecryptable envelopes kept for diagnosis: at most this many, for at most this long. */
const MAX_FAILED_ENVELOPES = 500;
const FAILED_ENVELOPE_DAYS = 30;
/** reset() waits at most this long for protocol work already holding the lock. */
const RESET_WAIT_MS = 30_000;
const RECONNECT_MS = 5_000;
/** Group state older than this is refetched before sending to the group. */
const GROUP_STALE_MS = 3600 * 1000;
/**
 * A sender's messages make us ask the groups server whether they are in a group at most this often per
 * group (a non-member's messages can't make us fetch more often than that).
 */
const GROUP_MEMBER_CHECK_MS = 60_000;
/** Messages at a newer revision refetch a group's state (to keep it current) at most this often. */
const GROUP_REVISION_REFETCH_MS = 10_000;
/** How long a group the server says we aren't in (403/404) is ignored for. */
const NOT_OUR_GROUP_MS = 3600 * 1000;
/** Fetches of groups we don't know yet, per sender and in total (made-up master keys each cost one). */
const NEW_GROUP_FETCHES_PER_SENDER_HOUR = 10;
const NEW_GROUP_FETCHES_PER_HOUR = 300;
/** Entries kept in each of the in-memory group maps above (the oldest go first). */
const MAX_TRACKED_GROUPS = 1000;
// Retry requests (src/signal/retry.ts). Desktop's RETRY_LIMIT is 5 per message; the hourly caps are ours.
const RETRIES_PER_MESSAGE = 5;
const RETRIES_PER_DEVICE_HOUR = 20;
// The overall cap is generous so one sender can't use it up for everyone; per message and per device
// limits do the bounding.
const RETRIES_PER_HOUR = 300;
const HOUR_MS = 3600 * 1000;
/** Refetch the sender certificate when it has less than this left. */
const SENDER_CERTIFICATE_MARGIN_MS = HOUR_MS;
/** Wait this long after a failed sender-certificate fetch before trying again. */
const SENDER_CERTIFICATE_RETRY_MS = 5 * 60 * 1000;

export type DirectorySync = { storageVersion: number; contacts: number; groups: number; fetched: number; errors: string[] };
/** A chat for list views: stored conversations plus known groups, with display names. */
export type Chat = { chat: string; name: string; kind: "direct" | "group" | "self"; messages: number; lastSentAt?: number; lastAuthor?: string; note?: string };
/** Group details without the master key. */
export type GroupInfo = Omit<GroupRecord, "masterKey" | "members" | "endorsements"> & { members?: { aci: string; name?: string; admin: boolean }[] };

export type DirectSendResult = {
	timestamp: number;
	/** Files sent (besides a long-text attachment). */
	attachments?: number;
	/** The text went as a long-text attachment; the body holds its start. */
	longText?: boolean;
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
	/** How many of the delivered copies went sealed sender (sender key or per member). */
	sealedSender: number;
	/** The sender-key attempt, when the group's endorsements allowed one. */
	senderKey?: { delivered: number; sharedWith: number; error?: string };
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
	/** Shown in the phone's list of linked devices (set when linking). */
	deviceName?: string;
	/** Largest attachment downloaded or sent (default 25 MB). */
	maxAttachmentBytes?: number;
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
	"chat_timers",
	"sender_key_shares",
	"counters",
	"last_errors",
	"identities",
] as const;

/**
 * One Signal account, acting as a linked device: linking, the receive loop, sending (1:1 and groups,
 * sealed sender and sender keys, attachments, quotes, reactions, mentions), contacts and groups,
 * retry requests and key maintenance. State lives in `db`, sealed with `storageKey`. Keep one instance
 * per account and database (in Workers, inside one Durable Object) and call `maintain()` when asked to
 * through `scheduleMaintenance`.
 */
/** Work for an account that reset() has forgotten since it started: it stops, writing nothing. */
export class AccountForgotten extends Error {
	constructor() {
		super("the account was forgotten (reset) meanwhile");
		this.name = "AccountForgotten";
	}
}

export class SignalClient {
	/** The host's database, as given: schema and reset() only. */
	readonly #db: SqlDatabase;
	/**
	 * The database for the current account (generation): what everything else reads and writes through.
	 * Objects built on it (stores, the message history) keep the view they were built with, so once
	 * reset() has moved on they refuse to touch the next account's data.
	 */
	#accountDb: SqlDatabase;
	/** Aborts the requests of sends in progress when reset() forgets the account. */
	#aborter = new AbortController();
	readonly #opts: SignalClientOptions;
	#sealerPromise?: Promise<Sealer>;
	#link: LinkState = { state: "unlinked" };
	#socket?: SignalSocket;
	#stores?: Promise<Partial<Record<OurIdentity, ProtocolStore>>>;
	#refreshing?: Promise<KeyRefreshResult>;
	#chat?: SignalSocket;
	#connecting?: Promise<void>;
	/**
	 * Bumped by reset(). Work started for the account before a reset (a socket, its handler, a sync,
	 * a key refresh, a link) checks it before writing, so nothing of the forgotten account comes back.
	 */
	#generation = 0;
	/** Serializes everything that touches session state: receiving and sending. */
	#protocol: Promise<unknown> = Promise.resolve();
	#receive: ReceiveState = { connected: false, envelopes: 0, stored: 0, ignored: 0, failed: 0, kinds: {} };
	#syncing?: Promise<DirectorySync>;
	/** Group fetches in flight, per group id, with the account generation and when each started. */
	#groupRefreshes = new Map<string, { generation: number; startedAt: number; promise: Promise<GroupRecord> }>();
	/** Fetches of groups we don't know yet, in flight, per group id. */
	#newGroupFetches = new Map<string, { generation: number; promise: Promise<GroupRecord | "not a member"> }>();
	/** When a sender's message last made us ask the server about a group, per "groupId sender". */
	#memberChecks = new Map<string, number>();
	/** When a message at a newer revision last made us refetch a group, per group id. */
	#groupNotedAt = new Map<string, number>();
	/** Groups the server says we aren't in (403/404), per id: until when to ignore them. */
	#notOurGroups = new Map<string, number>();
	/** Budget for fetching groups we don't know yet. */
	#groupLimits = new Limiter();
	#timers?: ChatTimers;
	#retryLimits = new Limiter();
	/** Access keys (base64) the server refused, per ACI: sends to them stay authenticated until the key changes. */
	#refusedAccessKeys = new Map<string, Set<string>>();
	/** A sender-certificate fetch in flight, shared by concurrent sends. */
	#senderCertificateFetch?: Promise<SendContext["sealedSender"]>;
	/** The sender certificate in kv, parsed; `owner` is the "aci.deviceId" it was fetched for. */
	#senderCertificate?: { owner: string; certificate: Uint8Array; expiresAt: number };
	/** After a failed sender-certificate fetch, sends stay authenticated until then. */
	#senderCertificateRetryAt = 0;
	/** A registration in progress (in memory: a restart starts over, as the server's session expires anyway). */
	#registration?: Registration;
	/** Whether this primary account has linked devices, and when that was checked. */
	#linkedDevices?: { any: boolean; at: number };

	/** Creates the tables if needed and reads the link state. Synchronous; no network. */
	constructor(opts: SignalClientOptions) {
		this.#opts = opts;
		this.#db = opts.db;
		this.#accountDb = this.#databaseFor(this.#generation);
		this.#createSchema();
		const meta = this.#get("account_meta");
		if (meta) {
			this.#link = JSON.parse(dec.decode(meta));
			// Earlier versions kept the phone number here, unsealed: rewrite without it.
			if (this.#link.state === "linked" && this.#link.number !== undefined) this.#setLink(this.#link);
		}
		if (this.#link.state === "linked") {
			// The phone number lives in the sealed secrets only; reading them puts it back into status().
			void this.#loadSecrets().catch(() => {});
			// A (re)started instance has no socket: let the watchdog connect right away.
			this.#schedule(Date.now() + 1000);
		}
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
		createTimerSchema(this.#db);
		createSenderKeySchema(this.#db);
		createCounterSchema(this.#db);
		createIdentitySchema(this.#db);
	}

	status(): LinkState {
		return this.#registration?.generation === this.#generation ? this.#registrationState() : this.#link;
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
		this.#registration = undefined; // linking instead of registering
		await this.#socket?.close().catch(() => {});

		const keys = newProvisioningKeyPair();
		const generation = this.#generation;
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
					const linking = this.#finishLink(body, keys.privateKey, generation);
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

	// --- standalone registration (a new primary account, no phone app) ---

	/**
	 * Starts registering `number` (E.164) as a new primary account, as Signal-Desktop's standalone
	 * registration does: a verification session that first wants a captcha. Taking over a number
	 * registers it here and signs out the phone that had it. Then submitCaptcha(), requestCode(),
	 * verifyCode().
	 */
	async startRegistration(number: string): Promise<LinkState> {
		if (this.#link.state === "linked") throw new Error("already linked or registered; reset() first");
		await this.#sealer(); // fail before any server call if the storage key is missing
		await this.#socket?.close().catch(() => {}); // a QR code shown for linking no longer applies
		const generation = this.#generation;
		const session = await createVerificationSession(number);
		this.#stillCurrent(generation);
		this.#registration = { number, session, codeRequested: false, generation };
		return this.#registrationState();
	}

	/** The captcha token (from signalcaptchas.org/registration/generate.html; "signalcaptcha://" is stripped). */
	async submitCaptcha(token: string): Promise<LinkState> {
		const r = this.#currentRegistration();
		r.session = await this.#registrationStep(r, () => submitCaptchaToSession(r.session.id, token));
		return this.#registrationState();
	}

	/** Asks for the code by SMS or voice call; `languages` (e.g. ["nb", "en"]) picks the message's language. */
	async requestCode(transport: VerificationTransport = "sms", languages: string[] = []): Promise<LinkState> {
		const r = this.#currentRegistration();
		r.session = await this.#registrationStep(r, () => requestVerificationCode(r.session.id, transport, languages));
		r.codeRequested = true;
		return this.#registrationState();
	}

	/**
	 * Submits the code and creates the account: new identity keys, registration ids, profile key and
	 * account entropy pool, this device as device 1. `discoverableByPhoneNumber`: whether people who
	 * have the number can find the account (default false). No PIN is set (SVR needs SGX attestation,
	 * which this library doesn't do), so the number can only be registered again with a new code.
	 */
	async verifyCode(code: string, opts: { discoverableByPhoneNumber?: boolean } = {}): Promise<LinkState> {
		const r = this.#currentRegistration();
		r.session = await this.#registrationStep(r, () => submitVerificationCode(r.session.id, code));
		if (!r.session.verified) throw new Error("the code wasn't accepted");
		const secrets = await this.#createPrimaryAccount(r.number, r.session.id, opts.discoverableByPhoneNumber ?? false);
		const sealed = await this.#sealSecrets(secrets);
		// Forgotten (reset) while the server created the account: it exists, but this instance keeps nothing.
		this.#stillCurrent(r.generation);
		this.#put("account_secrets", sealed);
		this.#registration = undefined;
		this.#stores = undefined;
		this.#linkedDevices = { any: false, at: Date.now() };
		this.#setLink({ state: "linked", aci: secrets.aci, pni: secrets.pni, number: secrets.number, deviceId: secrets.deviceId, linkedAt: secrets.linkedAt, primary: true });
		// The watchdog uploads one-time prekeys (none are on the server yet) and opens the chat socket.
		this.#schedule(Date.now());
		return this.#link;
	}

	#currentRegistration(): Registration {
		const r = this.#registration;
		if (!r || r.generation !== this.#generation) throw new Error("no registration in progress; startRegistration() first");
		return r;
	}

	/** Runs one session call; a refusal that carries the session state still updates it (e.g. new wait times). */
	async #registrationStep(r: Registration, call: () => Promise<VerificationSession>): Promise<VerificationSession> {
		try {
			const session = await call();
			this.#stillCurrent(r.generation);
			return session;
		} catch (e) {
			const session = (e as { session?: VerificationSession }).session;
			if (session && r.generation === this.#generation) r.session = session;
			throw e;
		}
	}

	#registrationState(): LinkState {
		const r = this.#registration;
		if (!r) return this.#link;
		const s = r.session;
		const step = s.requestedInformation.includes("captcha") && !s.allowedToRequestCode ? "captcha" : r.codeRequested ? "enter_code" : "request_code";
		return { state: "registering", number: r.number, step, nextSmsAt: s.nextSmsAt, nextCallAt: s.nextCallAt, nextVerificationAttemptAt: s.nextVerificationAttemptAt };
	}

	/** Signal-Desktop AccountManager.registerAsPrimaryDevice + #doCreateAccount (primary, with a number). */
	async #createPrimaryAccount(number: string, sessionId: string, discoverableByPhoneNumber: boolean): Promise<AccountSecrets> {
		const sig = signal();
		const newPair = () => identityPair(sig.WasmPrivateKey.generate().serialize());
		const aciPair = newPair();
		const pniPair = newPair();
		const publicKey = (pair: Uint8Array) => toBase64(sig.WasmIdentityKeyPair.deserialize(pair).public_key.serialize());
		const aciKeys = await lastResortKeys(aciPair);
		const pniKeys = await lastResortKeys(pniPair);
		// 16 random bytes, base64 without the "==" padding, as Desktop does.
		const password = toBase64(randomBytes(16)).slice(0, -2);
		const registrationId = sig.generateRegistrationId();
		const pniRegistrationId = sig.generateRegistrationId();
		const profileKey = randomBytes(32);
		const accountEntropyPool = generateAccountEntropyPool();
		const masterKey = libsignalExtra().master_key_from_entropy_pool(accountEntropyPool);
		const res = await registerAccount({
			number,
			sessionId,
			password,
			registrationId,
			pniRegistrationId,
			aciIdentityKey: publicKey(aciPair),
			pniIdentityKey: publicKey(pniPair),
			aciSignedPreKey: aciKeys.signed.upload,
			pniSignedPreKey: pniKeys.signed.upload,
			aciPqLastResortPreKey: aciKeys.kyber.upload,
			pniPqLastResortPreKey: pniKeys.kyber.upload,
			unidentifiedAccessKey: accessKey(profileKey),
			recoveryPassword: await registrationRecoveryPassword(masterKey),
			capabilities: CAPABILITIES,
			discoverableByPhoneNumber,
		});
		return {
			aci: res.aci,
			pni: res.pni,
			number: res.number ?? number,
			deviceId: 1,
			password,
			registrationId,
			pniRegistrationId,
			aciIdentityKeyPair: toBase64(aciPair),
			pniIdentityKeyPair: toBase64(pniPair),
			profileKey: toBase64(profileKey),
			accountEntropyPool,
			readReceipts: false,
			signedPreKeys: { aci: aciKeys.signed.stored, pni: pniKeys.signed.stored },
			kyberLastResortPreKeys: { aci: aciKeys.kyber.stored, pni: pniKeys.kyber.stored },
			linkedAt: Date.now(),
			primary: true,
		};
	}

	/**
	 * Whether our own account has other devices to send sync transcripts to. A linked device always
	 * has the primary; a primary has them only if it linked some (GET /v1/devices, checked at most
	 * every 10 minutes; assumed yes when the check fails, so nothing is lost).
	 */
	async #hasOtherDevices(a: AccountSecrets): Promise<boolean> {
		if (!a.primary) return true;
		const known = this.#linkedDevices;
		if (known && Date.now() - known.at < LINKED_DEVICES_CHECK_MS) return known.any;
		try {
			const res = await signalFetch(CHAT_HOST, "GET", "/v1/devices", { headers: { Authorization: deviceAuth(a) } });
			if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
			const devices = (JSON.parse(dec.decode(res.body)) as { devices?: { id: number }[] }).devices ?? [];
			const any = devices.some((d) => d.id !== a.deviceId);
			this.#linkedDevices = { any, at: Date.now() };
			return any;
		} catch (e) {
			console.warn("GET /v1/devices failed; sending sync transcripts anyway", e);
			return true;
		}
	}

	/**
	 * Forgets the linked account locally: closes the sockets and empties SIGNAL_TABLES. The device stays
	 * listed on the phone until removed there. Cancel the host's scheduled maintain() yourself.
	 */
	async reset(): Promise<LinkState> {
		// From here on the old account's database view refuses reads and writes, and its sends' requests
		// stop: nothing started for it can write anything back, however long it still runs.
		this.#generation++;
		this.#aborter.abort(new AccountForgotten());
		// Unlinked from the start: maintain() and the like stop at once. Until reset() returns, other
		// calls that read the account fail with AccountForgotten.
		this.#link = { state: "unlinked" };
		await this.#socket?.close().catch(() => {});
		const chat = this.#chat;
		this.#chat = undefined;
		this.#connecting = undefined; // a connect in flight is the forgotten account's; it closes its socket itself
		await chat?.close().catch(() => {});
		// Let protocol work holding the lock wind down (its requests were aborted and its writes fail);
		// work queued behind it sees the new generation and stops. Waiting is only for tidiness.
		let waited: ReturnType<typeof setTimeout> | undefined;
		await Promise.race([this.#protocol, new Promise((r) => (waited = setTimeout(r, RESET_WAIT_MS)))]);
		if (waited !== undefined) clearTimeout(waited);
		this.#db.transaction(() => {
			for (const t of SIGNAL_TABLES) this.#db.exec(`DELETE FROM ${t}`);
		});
		this.#createSchema();
		this.#accountDb = this.#databaseFor(this.#generation);
		this.#aborter = new AbortController();
		this.#timers = undefined;
		this.#stores = undefined;
		this.#refusedAccessKeys.clear();
		this.#memberChecks.clear();
		this.#groupRefreshes.clear();
		this.#newGroupFetches.clear();
		this.#groupNotedAt.clear();
		this.#notOurGroups.clear();
		this.#groupLimits = new Limiter();
		this.#senderCertificate = undefined;
		this.#senderCertificateFetch = undefined; // a fetch still in flight is for the forgotten account
		this.#senderCertificateRetryAt = 0;
		this.#registration = undefined;
		this.#linkedDevices = undefined;
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

	receiveStatus(): ReceiveState & { failedStored: number; messages: number; sendLog: number; lasting: { counters: Record<string, LastingCounter>; errors: Record<string, LastError> } } {
		const failedStored = this.#accountDb.exec<{ n: number }>("SELECT COUNT(*) AS n FROM failed_envelopes")[0]?.n ?? 0;
		const messages = this.#accountDb.exec<{ n: number }>("SELECT COUNT(*) AS n FROM messages")[0]?.n ?? 0;
		const c = this.#counters();
		return { ...this.#receive, failedStored, messages, sendLog: sendLogCount(this.#accountDb), lasting: { counters: c.counters(), errors: c.errors() } };
	}

	async messages(limit = 20, conversation?: string): Promise<StoredMessage[]> {
		return (await this.messageStore()).latest(Math.min(Math.max(limit, 1), 200), conversation);
	}

	async conversations(): Promise<Conversation[]> {
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
			const generation = this.#generation;
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
						onRequest: (req) => this.#onChatRequest(req, self, stores, pairs, messages, identities, generation),
						onClose: (code, reason) => {
							if (generation !== this.#generation) return; // a socket of the forgotten account
							if (this.#chat === chat) this.#chat = undefined;
							this.#receive.connected = false;
							this.#receive.lastClose = `${new Date().toISOString()} ${code} ${reason}`;
							this.#schedule(Date.now() + RECONNECT_MS);
						},
					},
					{ Authorization: deviceAuth(a), "X-Signal-Receive-Stories": "false" },
				);
				if (generation !== this.#generation) {
					await chat.close().catch(() => {});
					return;
				}
				this.#chat = chat;
				this.#receive.connected = true;
				this.#receive.connectedAt = Date.now();
			} catch (e) {
				if (generation !== this.#generation) throw e; // a connect of the forgotten account: not this one's state
				this.#receive.lastError = `${new Date().toISOString()} connect: ${e}`;
				this.#lasting((c) => c.error("connect", String(e)));
				// 401/403 on the upgrade: the device was removed or the password is wrong. Retrying won't help.
				if (/HTTP 40[13]\b/.test(String(e))) this.#receive.authFailed = true;
				throw e;
			}
		})().finally(() => {
			if (this.#connecting === connecting) this.#connecting = undefined;
		});
		const connecting = this.#connecting;
		return connecting;
	}

	async #onChatRequest(
		req: WsRequest,
		self: Self,
		stores: Partial<Record<OurIdentity, ProtocolStore>>,
		pairs: Partial<Record<OurIdentity, Uint8Array>>,
		messages: MessageStore,
		identities: IdentityLog,
		generation: number,
	): Promise<number> {
		// A socket of an account forgotten since (reset): not ours to process; it is being closed.
		if (generation !== this.#generation) return 503;
		const db = this.#accountDb;
		if (req.verb === "PUT" && req.path === "/api/v1/queue/empty") {
			this.#receive.queueEmptyAt = Date.now();
			return 200;
		}
		if (req.verb !== "PUT" || req.path !== "/api/v1/message") return 400;

		const body = req.body ?? new Uint8Array(0);
		this.#receive.envelopes++;
		this.#lasting((c) => c.bump("receive:envelopes"));
		this.#receive.lastEnvelopeAt = Date.now();
		// A redelivered envelope (e.g. the instance restarted before the ack) can't decrypt again: skip it.
		const seen = new SeenEnvelopes(db);
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
			const r = await this.#withProtocolLock(generation, async () => {
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
				// Outside the protocol lock (may fetch group state): Signal's apps drop group messages from
				// non-members, and so do we, before anything is stored or reported.
				await this.#dropNonMembers(generation, r.parsed, r.sender, self);
				this.#stillCurrent(generation);
				await this.#checkQuotes(r.parsed.records, messages);
				if (r.identityChanged) {
					this.#count("identity-change");
					await messages.add([identityChangeRecord(r.sender, r.senderDevice)], r.serverGuid, Date.now());
				}
				const inserted: MessageRecord[] = [];
				const added = await messages.add(r.parsed.records, r.serverGuid, Date.now(), inserted);
				// Stored first (the envelope already counts as seen, so a restart mid-download mustn't lose
				// it), then a long message's full text replaces the short body: only for records stored just
				// now, or a later message reusing a timestamp could rewrite an earlier one.
				await this.#expandLongText(inserted, messages);
				this.#stillCurrent(generation); // what follows writes through fresh helpers
				this.#receive.stored += added;
				this.#lasting((c) => c.bump("receive:stored", added));
				if (r.parsed.decryptionError) {
					const request = r.parsed.decryptionError;
					void this.#answerRetryRequest(generation, r.sender, r.senderDevice, request, stores, identities, messages).catch((e) => this.#retryError("answering retry request", e));
				}
				// A copy we already had (e.g. resent after a retry request) mustn't start another reply run.
				if (added) this.#notifyMessages(r.parsed.records, self);
				// Outside the protocol lock: fetching group state is network-only.
				for (const g of r.parsed.groups) void this.#noteGroup(generation, g.masterKey, g.revision, r.sender === self.aci).catch((e) => console.error("group refresh failed", e));
				for (const t of r.parsed.timers) if (this.#chatTimers().apply(t)) this.#count("timer:updated");
			}
		} catch (e) {
			if (generation !== this.#generation) return 503; // forgotten meanwhile: store nothing
			// Ack anyway, or Signal redelivers it forever; keep it sealed so it can be reprocessed after a fix,
			// and ask the sender for it again when we know who sent it.
			if (e instanceof DecryptFailure) {
				const failed = e.failed;
				void this.#requestResend(generation, failed, stores, identities, messages).catch((err) => this.#retryError("sending retry request", err));
			}
			this.#receive.failed++;
			this.#lasting((c) => c.bump("receive:failed"));
			this.#receive.lastError = `${new Date().toISOString()} envelope: ${e}`;
			this.#lasting((c) => c.error("envelope", String(e)));
			console.error("envelope failed", e);
			const sealed = await (await this.#sealer()).seal("failed_envelopes", body);
			db.exec("INSERT INTO failed_envelopes (received_at, error, envelope) VALUES (?, ?, ?)", Date.now(), String(e).slice(0, 500), sealed);
		}
		return 200;
	}

	// --- retry requests (src/signal/retry.ts) ---

	/** We couldn't decrypt a message: ask its sender (all their devices; the request names the one that sent it) to resend. */
	async #requestResend(generation: number, failed: FailedMessage, stores: Partial<Record<OurIdentity, ProtocolStore>>, identities: IdentityLog, messages: MessageStore): Promise<void> {
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
		await this.#withProtocolLock(generation, async () => {
			const ctx = this.#sendContext(a, stores, identities, undefined, sealedSender);
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
		generation: number,
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
		const shares = this.#senderKeyShares();
		await this.#withProtocolLock(generation, async () => {
			// No ratchet key: a sender-key message failed, so that device lacks our sender key. The next group
			// send shares it again (Desktop removes the device from the group's sender-key members). Inside
			// the lock, so a group send in progress can't write its older device list back over this.
			if (!req.ratchetKey) shares.forgetDevice(requester, requesterDevice);
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
			const ctx = this.#sendContext(a, stores, identities, undefined, sealedSender);
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
		if (e instanceof AccountForgotten) return; // the account it was for is gone: nothing to record
		this.#count("retry-request:failed");
		this.#receive.lastRetryError = `${new Date().toISOString()} ${what}: ${e}`;
		this.#lasting((c) => c.error("retry request", `${what}: ${e}`));
		console.error(what, e);
	}

	/** Counts and last errors kept across restarts (src/counters.ts). */
	#counters(): Counters {
		return new Counters(this.#accountDb);
	}

	#senderKeyShares(): SenderKeyShares {
		return new SenderKeyShares(this.#accountDb);
	}

	#chatTimers(): ChatTimers {
		return (this.#timers ??= new ChatTimers(this.#accountDb));
	}

	/**
	 * Note to Self that only our other devices get. Not stored and not kept in the send log, so it fits
	 * one-time codes that nothing reading the message history should see.
	 */
	async notifySelf(body: string): Promise<void> {
		const generation = this.#generation;
		const a = await this.#loadSecrets();
		const stores = await this.#loadStores();
		const identities = await this.#identities();
		if (!(await this.#hasOtherDevices(a))) throw new Error("this account has no other devices to show a Note to Self on");
		await this.#withProtocolLock(generation, async () => {
			const timestamp = Date.now();
			const ctx = this.#sendContext(a, stores, identities);
			// Note to Self's own timer, or the phone would read the code as turning it off.
			const expiry = this.#chatTimers().forSend(`aci:${a.aci}`);
			await sendToServiceId(ctx, a.aci, contentWithSentTranscript(a.aci, timestamp, dataMessage(body, timestamp, undefined, undefined, [], expiry), []), timestamp);
		});
	}

	// --- sending ---

	/**
	 * Sends a message to `aci:<uuid>` (or a bare UUID), `"self"` (Note to Self) or `group:<base64 id>`,
	 * plus the sync transcript that makes it appear on our other devices (for Note to Self the only
	 * copy, as in Desktop). Text past 2000 bytes goes as a long-text attachment; `files` are uploaded
	 * first; `extras` quote or react to a stored message by its sentAt. "@[aci:<uuid>]" in group text
	 * becomes a mention.
	 */
	async sendText(to: string, body: string, files: OutgoingFile[] = [], extras: MessageExtras = {}): Promise<DirectSendResult | GroupSendResult> {
		if (extras.reaction && (body.trim() || files.length || extras.replyTo !== undefined)) throw new Error("a reaction is sent on its own, without text, attachments or a reply");
		if (!body.trim() && !files.length && !extras.reaction) throw new Error("empty message");
		const generation = this.#generation;
		const a = await this.#loadSecrets();
		// Uploads happen before any lock (network only), and only once the target checks out: the same
		// pointers go to every recipient.
		const prepare = (conversation: string, members?: string[]) => this.#prepareOutgoing(a, body, files, extras, conversation, members);
		if (to.startsWith("group:")) return this.#sendGroupText(generation, to.slice(6), prepare, extractMentions(body).mentions.map((m) => m.aci));
		const target = to === "self" ? a.aci : to.replace(/^aci:/, "").toLowerCase();
		if (!ACI_PATTERN.test(target)) throw new Error("recipient must be an ACI (UUID) or \"self\"");
		const out = await prepare(`aci:${target}`);
		const stores = await this.#loadStores();
		const messages = await this.messageStore();
		const identities = await this.#identities();
		const isSelf = target === a.aci;
		// Network and storage lookups before taking the lock.
		const key = isSelf ? undefined : await this.#accessKey(target);
		const sealedSender = key && (await this.#sealedSender(a));
		const sendLog = await this.#sendLog();
		// A primary account without linked devices has nobody to send the transcript to (Note to Self is then kept here only).
		const sync = await this.#hasOtherDevices(a);
		return this.#withProtocolLock(generation, async () => {
			const timestamp = Date.now();
			const ctx = this.#sendContext(a, stores, identities, sendLog, sealedSender);
			// Our profile key lets the recipient decrypt our name and avatar.
			const expiry = this.#chatTimers().forSend(`aci:${target}`);
			const data = dataMessage(out.body, timestamp, isSelf ? undefined : fromBase64(a.profileKey), undefined, out.pointers, expiry, {
				quote: out.quote?.bytes,
				reaction: out.reaction?.bytes,
				mentions: out.mentions,
			});
			const result: DirectSendResult = { timestamp };
			if (!isSelf) {
				result.recipientDevices = await sendToServiceId(ctx, target, contentWithData(data), timestamp, { accessKey: key, contentHint: CONTENT_HINT.RESENDABLE });
				result.sealedSender = !!ctx.sealedTo?.includes(target);
				this.#count(result.sealedSender ? "send:sealed" : "send:authenticated");
			}
			if (!sync) {
				result.syncedDevices = [];
			} else {
				try {
					result.syncedDevices = await sendToServiceId(ctx, a.aci, contentWithSentTranscript(target, timestamp, data, isSelf ? [] : [target], ctx.sealedTo), timestamp);
				} catch (e) {
					if (isSelf) throw e;
					result.syncError = String(e); // delivered, but our phone won't show it
				}
			}
			if (out.stored.length) result.attachments = out.stored.length;
			if (out.longText) result.longText = true;
			await messages.add([outgoingRecord(`aci:${target}`, a, timestamp, out, expiry)], `local-${timestamp}`, timestamp);
			result.safetyNumberChanged = await this.#recordIdentityChanges(ctx, messages);
			return result;
		});
	}

	/**
	 * Uploads what a message needs besides its body: text past MAX_TEXT_BYTES as a long-text attachment
	 * (listed first, as Desktop; the body keeps the start), then each file: a received attachment
	 * forwarded by "<message>/<index>", text, or base64 data.
	 */
	async #prepareOutgoing(a: AccountSecrets, body: string, files: OutgoingFile[], extras: MessageExtras, conversation: string, members?: string[]): Promise<Outgoing> {
		if (files.length > MAX_SEND_FILES) throw new Error(`at most ${MAX_SEND_FILES} attachments per message`);
		const auth = deviceAuth(a);
		// "@[aci:<uuid>]" tokens become mention placeholders; the ranges index the full text (a long text's
		// attachment carries it whole, and receivers apply the ranges to that).
		const extracted = body.trim() ? extractMentions(body) : { body: "", mentions: [] }; // whitespace beside attachments isn't a body
		const text = extracted.body;
		checkMentions(extracted.mentions, members); // before any upload
		const out: Outgoing = { body: text, fullBody: text, pointers: [], stored: [], longText: false, mentions: extracted.mentions };
		// Quote / reaction targets: a stored message in this very chat, by the id MCP listings show (its sentAt).
		const store = await this.messageStore();
		const target = async (sentAt: number) => {
			const m = await store.findSent(conversation, sentAt);
			if (!m) throw new Error(`no message with id ${sentAt} in this chat`);
			// Quote.authorAci / Reaction.targetAuthorAci name an ACI; a PNI-only author can't be named there.
			if (!ACI_PATTERN.test(m.author)) throw new Error(`message ${sentAt} has no ACI author to name`);
			return m;
		};
		if (extras.replyTo !== undefined) {
			const m = await target(extras.replyTo);
			const quoted = m.body ? truncateUtf8(m.body, MAX_TEXT_BYTES) : undefined;
			// Only the mentions that apply to the (possibly cut) quoted text, as showMentions shows them: a
			// received range over ordinary words, or a second one on the same placeholder, mustn't be quoted
			// back. None in 1:1 chats (no member list), where mentions aren't sent.
			const mentions = quoted === undefined || !members ? [] : validMentions(quoted, m.mentions);
			out.quote = {
				bytes: quoteMessage(m.sentAt, m.author, quoted, mentions),
				record: { id: m.sentAt, author: m.author, text: quoted, ...(mentions.length ? { mentions } : {}) },
			};
		}
		if (extras.reaction) {
			const { emoji, targetSentAt, remove } = extras.reaction;
			if (!emoji.trim() || [...emoji].length > 8) throw new Error("reaction must be a single emoji");
			const m = await target(targetSentAt);
			out.reaction = {
				bytes: reactionMessage(emoji, m.author, m.sentAt, !!remove),
				record: { emoji, remove: !!remove, targetAuthor: m.author, targetSentAt: m.sentAt },
			};
		}
		const bodyBytes = enc.encode(text);
		if (bodyBytes.length > MAX_LONG_TEXT_BYTES) throw new Error(`message longer than ${MAX_LONG_TEXT_BYTES} bytes`);
		// Independent uploads run concurrently; the long text stays first in the list, as Desktop sends it.
		const [longText, ...uploaded] = await Promise.all([
			bodyBytes.length > MAX_TEXT_BYTES ? uploadAttachment(auth, bodyBytes) : Promise.resolve(undefined),
			...files.map(async (f) => {
				const file = await this.#outgoingFile(f);
				return { file, upload: await uploadAttachment(auth, file.data) };
			}),
		]);
		if (longText) {
			out.pointers.push(attachmentPointer(longText, { contentType: LONG_TEXT_TYPE }));
			out.body = truncateUtf8(text, MAX_TEXT_BYTES);
			out.longText = true;
		}
		for (const { file, upload: u } of uploaded) {
			const { contentType, fileName, caption, voiceNote } = file;
			out.pointers.push(attachmentPointer(u, { contentType, fileName, caption, voiceNote }));
			out.stored.push({ contentType, fileName, size: u.size, caption, voiceNote, pointer: { cdnNumber: u.cdnNumber, cdnKey: u.cdnKey, key: u.key, digest: u.digest } });
		}
		this.#count("send:attachments uploaded", out.pointers.length);
		return out;
	}

	/** The bytes and metadata of one file to send; checks the shape too, since the admin route passes raw JSON. */
	async #outgoingFile(f: OutgoingFile): Promise<{ data: Uint8Array; contentType: string; fileName?: string; caption?: string; voiceNote?: boolean }> {
		const caption = typeof f.caption === "string" && f.caption ? f.caption : undefined;
		let file: { data: Uint8Array; contentType: string; fileName?: string; caption?: string; voiceNote?: boolean };
		if ("ref" in f && typeof f.ref === "string") {
			const m = /^(\d+)\/(\d+)$/.exec(f.ref);
			if (!m) throw new Error(`attachment ref must look like "123/0", not ${JSON.stringify(f.ref)}`);
			const got = await this.attachment(Number(m[1]), Number(m[2]));
			file = { data: got.data, contentType: got.contentType ?? "application/octet-stream", fileName: got.fileName, caption, voiceNote: got.voiceNote };
		} else if ("text" in f && typeof f.text === "string" && typeof f.fileName === "string") {
			file = { data: enc.encode(f.text), contentType: f.contentType ?? "text/plain", fileName: f.fileName, caption };
		} else if ("base64" in f && typeof f.base64 === "string" && typeof f.contentType === "string") {
			let data: Uint8Array;
			try {
				data = fromBase64(f.base64);
			} catch {
				throw new Error(`attachment ${f.fileName ?? f.contentType}: base64 doesn't decode`);
			}
			file = { data, contentType: f.contentType, fileName: f.fileName, caption };
		} else {
			throw new Error("each attachment needs {ref}, {fileName, text} or {contentType, base64}");
		}
		const label = file.fileName ?? file.contentType;
		if (!file.data.length) throw new Error(`attachment ${label} is empty`);
		if (file.data.length > this.#maxAttachmentBytes) throw new Error(`attachment ${label} is ${file.data.length} bytes; the limit is ${this.#maxAttachmentBytes}`);
		return file;
	}

	/**
	 * Group text, sent as one 1:1-encrypted copy per member (Desktop's non-sender-key path), then a
	 * sync transcript listing who got it. Member list and revision come from the groups server.
	 */
	async #sendGroupText(generation: number, groupId: string, prepare: (conversation: string, members: string[]) => Promise<Outgoing>, mentioned: string[] = []): Promise<GroupSendResult> {
		const a = await this.#loadSecrets();
		const dir = await this.#directoryFor(generation);
		let g = await dir.group(groupId);
		if (!g) throw new Error(`unknown group ${groupId}; run a directory sync or wait for a message from it`);
		// Refetch when stale, or when a mention names someone the cached list lacks (they may have just
		// joined); a minute's grace keeps a mistyped mention from refetching on every try.
		const lacksMentioned = (r: NonNullable<typeof g>) => mentioned.some((aci) => !r.members?.some((m) => m.aci === aci));
		if (!g.fetchedAt || !g.members || Date.now() - g.fetchedAt > GROUP_STALE_MS || (lacksMentioned(g) && Date.now() - g.fetchedAt > 60_000)) {
			g = await this.#refreshGroup(g, 0, generation);
		}
		if (g.fetchError) throw new Error(`can't send to this group: ${g.fetchError}`);
		if (g.terminated) throw new Error("this group has been ended");
		const me = g.members?.find((m) => m.aci === a.aci);
		if (!me) throw new Error("this account is not a member of the group");
		if (g.announcementsOnly && !me.admin) throw new Error("only admins can send in this group");
		const group = g;
		const memberAcis = (group.members ?? []).map((m) => m.aci);
		const recipients = memberAcis.filter((aci) => aci !== a.aci);
		const out = await prepare(`group:${group.id}`, memberAcis);
		const stores = await this.#loadStores();
		const messages = await this.messageStore();
		const identities = await this.#identities();
		const keys = new Map<string, Uint8Array | undefined>();
		// Group records are decrypted once here, not once per member whose key isn't in this group's state.
		const allGroups = await dir.groups();
		for (const m of group.members ?? []) if (m.aci !== a.aci) keys.set(m.aci, await this.#accessKey(m.aci, m.profileKey, allGroups));
		// The certificate serves both sealed paths: access keys per member, or the group's endorsements.
		const endorsements = senderKeyUsable(recipients, group.endorsements) ? group.endorsements : undefined;
		const sealedSender = [...keys.values()].some(Boolean) || endorsements ? await this.#sealedSender(a) : undefined;
		const groupIdBytes = fromBase64(group.id);
		const sendLog = await this.#sendLog();
		const shares = this.#senderKeyShares();
		const sync = await this.#hasOtherDevices(a);
		return this.#withProtocolLock(generation, async () => {
			const timestamp = Date.now();
			const ctx = this.#sendContext(a, stores, identities, sendLog, sealedSender);
			const expiry = this.#chatTimers().forSend(`group:${group.id}`, group.disappearingTimer);
			const data = dataMessage(out.body, timestamp, fromBase64(a.profileKey), { masterKey: fromBase64(group.masterKey), revision: group.revision ?? 0 }, out.pointers, expiry, {
				quote: out.quote?.bytes,
				reaction: out.reaction?.bytes,
				mentions: out.mentions,
			});
			const content = contentWithData(data);
			const delivered: string[] = [];
			const failed: { aci: string; error: string }[] = [];
			// Sender key first (one encryption, one request), as Desktop; whoever it didn't reach gets
			// a message of their own below.
			let senderKey: { delivered: number; sharedWith: number; error?: string } | undefined;
			if (endorsements && ctx.sealedSender) {
				try {
					const r = await sendWithSenderKey({
						ctx,
						groupId: group.id,
						masterKey: fromBase64(group.masterKey),
						members: memberAcis,
						recipients,
						endorsements,
						content,
						timestamp,
						accessKeys: keys,
						shares,
					});
					delivered.push(...r.delivered);
					for (const aci of r.unregistered) failed.push({ aci, error: "not registered with Signal any more" });
					senderKey = { delivered: r.delivered.length, sharedWith: r.sharedWith };
					this.#count("send:sender-key", r.delivered.length);
				} catch (e) {
					senderKey = { delivered: 0, sharedWith: 0, error: String(e).slice(0, 200) };
					this.#count("send:sender-key failed");
					console.warn("sender-key send failed; sending to each member", e);
				}
			}
			const done = new Set([...delivered, ...failed.map((f) => f.aci)]);
			for (const aci of recipients) {
				if (done.has(aci)) continue;
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
				senderKey,
				failed,
			};
			if (!sync) {
				result.syncedDevices = [];
			} else {
				try {
					result.syncedDevices = await sendToServiceId(ctx, a.aci, contentWithSentTranscript(undefined, timestamp, data, delivered, ctx.sealedTo), timestamp);
				} catch (e) {
					result.syncError = String(e);
				}
			}
			await messages.add([outgoingRecord(`group:${group.id}`, a, timestamp, out, expiry)], `local-${timestamp}`, timestamp);
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
					await this.#keepSenderCertificate(owner, certificate, current);
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
	async #keepSenderCertificate(owner: string, certificate: Uint8Array, current: () => boolean): Promise<void> {
		const expiresAt = libsignalExtra().sender_certificate_expiration(certificate);
		const sealed = await (await this.#sealer()).seal(`sender_certificate|${owner}`, certificate);
		if (!current()) return; // fetched for an account forgotten meanwhile
		this.#put("sender_certificate", sealed);
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

	/**
	 * What a send needs; built inside the protocol lock, so the abort signal is this account's. The
	 * sealed-sender part remembers access keys the server refused, so later sends skip them.
	 */
	#sendContext(a: AccountSecrets, stores: Partial<Record<OurIdentity, ProtocolStore>>, identities: IdentityLog, sendLog?: SendLog, sealedSender?: SendContext["sealedSender"]): SendContext {
		return {
			ourAci: a.aci,
			ourDeviceId: a.deviceId,
			auth: deviceAuth(a),
			store: stores.aci!,
			identities,
			sendLog,
			signal: this.#aborter.signal,
			sealedSender,
			onUnsealed: (_serviceId, reason) => this.#count(`sealed-sender:skipped (${reason})`),
			onAccessKeyRefused: (serviceId, key) => {
				let refused = this.#refusedAccessKeys.get(serviceId);
				if (!refused) this.#refusedAccessKeys.set(serviceId, (refused = new Set()));
				refused.add(toBase64(key));
				this.#count("sealed-sender:access key refused");
			},
		};
	}

	#identities(): Promise<IdentityLog> {
		return this.#sealer().then((s) => new IdentityLog(this.#accountDb, s));
	}

	// --- groups and contacts ---

	/** Reads the group list and contacts from the storage service, then fetches every group's state. */
	syncDirectory(): Promise<DirectorySync> {
		this.#syncing ??= this.#syncDirectory().finally(() => (this.#syncing = undefined));
		return this.#syncing;
	}

	async #syncDirectory(): Promise<DirectorySync> {
		const generation = this.#generation;
		const a = await this.#loadSecrets();
		const dir = await this.#directoryFor(generation);
		const snapshot = await readStorage(deviceAuth(a), this.#accountMasterKey(a));
		this.#stillCurrent(generation);
		await dir.replaceContacts(snapshot.contacts);
		const known = new Map((await dir.groups()).map((g) => [g.id, g]));
		for (const sg of snapshot.groups) {
			const id = groupIdFromMasterKey(sg.masterKey);
			const g: GroupRecord = { ...(known.get(id) ?? { id, masterKey: toBase64(sg.masterKey) }), source: "storage", blocked: sg.blocked, archived: sg.archived };
			this.#stillCurrent(generation);
			await dir.putGroup(g);
			known.set(id, g);
		}
		const errors: string[] = [];
		let fetched = 0;
		for (const g of known.values()) {
			try {
				const next = await this.#refreshGroup(g, 0, generation);
				if (next.fetchError) errors.push(`${g.id.slice(0, 8)}…: ${next.fetchError}`);
				else fetched++;
			} catch (e) {
				errors.push(`${g.id.slice(0, 8)}…: ${e}`);
			}
		}
		this.#stillCurrent(generation);
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

	// --- attachments (src/protocol/attachments.ts) ---

	/**
	 * A message longer than about 2 KB arrives with only its start as the body and the whole text as a
	 * `text/x-signal-plain` attachment (Desktop `sendNormalMessage`; its apps show the attachment as the
	 * body). Fetch it and store the full text as the body, so readers see all of
	 * it. On failure or timeout the record keeps the short body and the attachment reference.
	 */
	async #expandLongText(records: MessageRecord[], messages: MessageStore): Promise<void> {
		const long = records.filter((rec) => rec.attachments?.some((a) => a.contentType === LONG_TEXT_TYPE));
		if (!long.length) return;
		const copies = long.map((rec) => structuredClone(rec));
		// The sender chooses the pointer: the download is capped at the long-text limit and cancelled
		// (connection closed) when the timeout passes, so it can't keep running or grow unseen.
		const r = await expandLongText(copies, MAX_LONG_TEXT_BYTES, (a) =>
			downloadAttachment(a.pointer!, a.size, { maxBytes: MAX_LONG_TEXT_BYTES, signal: AbortSignal.timeout(LONG_TEXT_TIMEOUT_MS) }),
		);
		for (const rec of copies) if (!rec.attachments?.some((a) => a.contentType === LONG_TEXT_TYPE)) await messages.replace(rec);
		this.#count("receive:long text expanded", r.expanded);
		this.#count("receive:long text not expanded", r.failed);
	}

	/** Downloads and decrypts attachment `index` of stored message `messageId` (the row id). */
	async attachment(messageId: number, index: number, maxBytes = this.#maxAttachmentBytes): Promise<{ contentType?: string; fileName?: string; voiceNote?: boolean; data: Uint8Array }> {
		const m = await (await this.messageStore()).get(messageId);
		const a = m?.attachments?.[index];
		if (!a) throw new Error(`no attachment ${messageId}/${index}`);
		if (!a.pointer) throw new Error("this attachment was received before the Worker kept download keys, or has none");
		if (a.size !== undefined && a.size > maxBytes) throw new Error(`attachment is ${a.size} bytes; the limit is ${maxBytes}`);
		return { contentType: a.contentType, fileName: a.fileName, voiceNote: a.voiceNote, data: await downloadAttachment(a.pointer, a.size, { maxBytes }) };
	}

	get #maxAttachmentBytes(): number {
		return this.#opts.maxAttachmentBytes ?? DEFAULT_MAX_ATTACHMENT_BYTES;
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

	/**
	 * Quotes carry the quoted text as the sender writes it. Where the quoted message is stored (same
	 * chat, id and author), its stored text replaces the sender's version; otherwise the quote is
	 * marked unverified, so nobody can put words in another person's mouth unnoticed.
	 */
	async #checkQuotes(records: MessageRecord[], messages: MessageStore): Promise<void> {
		for (const rec of records) {
			const q = rec.quote;
			if (!q) continue;
			const stored = q.id !== undefined && q.author ? await messages.findSent(rec.conversation, q.id, q.author) : undefined;
			if (stored) {
				// Text and mentions both from what was stored: the sender's ranges could put other names on
				// the stored text's placeholders.
				q.text = stored.body !== undefined ? truncateUtf8(stored.body, MAX_TEXT_BYTES) : undefined;
				const mentions = q.text === undefined ? [] : validMentions(q.text, stored.mentions);
				if (mentions.length) q.mentions = mentions;
				else delete q.mentions;
				q.verified = true;
			} else {
				q.verified = false;
			}
		}
	}

	/** ACI → display name, from storage-service contacts. */
	async names(): Promise<Record<string, string>> {
		return Object.fromEntries(await this.#names(await this.directory()));
	}

	async #names(dir: Directory): Promise<Map<string, string>> {
		return new Map((await dir.contacts()).filter((c) => c.name).map((c) => [c.aci, c.name!]));
	}

	/**
	 * Keeps a group named in a stored message current: fetches its state at a newer revision than stored,
	 * at most once per GROUP_REVISION_REFETCH_MS per group. Groups we don't know yet are fetched here only
	 * when our own devices named them (a group the owner just made or joined); others' messages had theirs
	 * fetched by the membership check.
	 */
	async #noteGroup(generation: number, masterKey: Uint8Array, revision: number, fromOurDevices: boolean): Promise<void> {
		const id = groupIdFromMasterKey(masterKey);
		const now = Date.now();
		if (now - (this.#groupNotedAt.get(id) ?? 0) < GROUP_REVISION_REFETCH_MS) return;
		const known = await (await this.#directoryFor(generation)).group(id);
		if (known?.revision !== undefined && known.revision >= revision) return;
		if (!known && (!fromOurDevices || (this.#notOurGroups.get(id) ?? 0) > now)) return;
		remember(this.#groupNotedAt, id, now);
		if (known) await this.#refreshGroup(known, 0, generation);
		else await this.#fetchNewGroup(generation, id, masterKey);
	}

	/**
	 * Whether `sender` is a member of a group their message names. The stored member list answers when it
	 * lists them at the message's revision; otherwise the groups server is asked (someone just added is
	 * then found), at most once per GROUP_MEMBER_CHECK_MS per group and sender, so a non-member's
	 * messages can't make us fetch more often than that. Groups we don't know yet are fetched within
	 * budgets and stored only once the server hands us their state as a member.
	 * "unknown": can't tell right now (network trouble, or no member list yet); the message is kept.
	 */
	async #senderInGroup(generation: number, id: string, masterKey: Uint8Array | undefined, revision: number | undefined, sender: string): Promise<"member" | "not a member" | "unknown"> {
		const askedAt = Date.now();
		const known = await (await this.#directoryFor(generation)).group(id);
		// A group the server lately said we aren't in, unless it has been stored since (we joined).
		if (!known && (this.#notOurGroups.get(id) ?? 0) > askedAt) return "not a member";
		const listed = (g: GroupRecord | undefined) => (!g?.members ? "unknown" : g.members.some((m) => m.aci === sender) ? "member" : "not a member");
		const newer = revision !== undefined && (known?.revision === undefined || known.revision < revision);
		// A stored fetchError (we were out of the group then, or, from earlier versions, a failed fetch)
		// means the server is asked again.
		if (!known?.fetchError && listed(known) === "member" && !newer) return "member";
		const key = `${id} ${sender}`;
		// Without a fresh answer from the server, the stored member list decides.
		if (askedAt - (this.#memberChecks.get(key) ?? 0) < GROUP_MEMBER_CHECK_MS) return listed(known);
		if (!known) {
			if (!masterKey) return "not a member";
			const budget = this.#newGroupBudget(sender);
			// This sender named more new groups than anyone joins in an hour: theirs are dropped. When the
			// overall budget is what ran out, the message is kept, as when the server can't be reached.
			if (budget === "sender") {
				this.#count("ignored:too many new groups from one sender");
				return "not a member";
			}
			if (budget === "overall") {
				this.#count("receive:group not checked (fetch budget used up)");
				return "unknown";
			}
		}
		remember(this.#memberChecks, key, askedAt);
		try {
			// A fetch that started before we asked may predate the sender joining: wait for a newer one.
			const g = known ? await this.#refreshGroup(known, askedAt, generation) : await this.#fetchNewGroup(generation, id, masterKey!);
			if (g === "not a member" || g.fetchError) return "not a member"; // the server says we aren't in it
			return listed(g);
		} catch (e) {
			if (e instanceof AccountForgotten) throw e;
			console.error("group fetch failed", e);
			return listed(known);
		}
	}

	/**
	 * One more fetch of a group we don't know yet, within the hourly budgets: true, or which budget is
	 * used up ("sender": this sender's; "overall").
	 */
	#newGroupBudget(sender: string): true | "sender" | "overall" {
		const own = `new:${sender}`;
		const refused = this.#groupLimits.refusal([
			{ key: own, max: NEW_GROUP_FETCHES_PER_SENDER_HOUR, windowMs: HOUR_MS },
			{ key: "new", max: NEW_GROUP_FETCHES_PER_HOUR, windowMs: HOUR_MS },
		]);
		return refused === undefined ? true : refused === own ? "sender" : "overall";
	}

	/**
	 * Fetches a group we don't know yet (one fetch per group at a time) and stores it if the server hands
	 * us its state. "not a member": the server says we aren't in it (403/404); then it is ignored for
	 * NOT_OUR_GROUP_MS. Other failures (network, 429, 5xx) throw and leave nothing behind.
	 */
	#fetchNewGroup(generation: number, id: string, masterKey: Uint8Array): Promise<GroupRecord | "not a member"> {
		const running = this.#newGroupFetches.get(id);
		if (running?.generation === generation) return running.promise;
		const promise = (async (): Promise<GroupRecord | "not a member"> => {
			this.#stillCurrent(generation);
			const dir = await this.#directoryFor(generation);
			try {
				const state = await fetchGroupState(masterKey, await this.#groupCredential());
				const g: GroupRecord = { id, masterKey: toBase64(masterKey), source: "message", ...state };
				await dir.putGroup(g); // refused if the account was forgotten meanwhile
				this.#notOurGroups.delete(id);
				return g;
			} catch (e) {
				if (e instanceof GroupFetchError && notAMember(e)) {
					this.#stillCurrent(generation);
					remember(this.#notOurGroups, id, Date.now() + NOT_OUR_GROUP_MS);
					return "not a member";
				}
				throw e;
			}
		})().finally(() => {
			if (this.#newGroupFetches.get(id)?.promise === promise) this.#newGroupFetches.delete(id);
		});
		this.#newGroupFetches.set(id, { generation, promise });
		return promise;
	}

	/**
	 * Drops group records, timers and group contexts whose sender isn't a member of that group, as
	 * Signal's apps do: knowing a group's master key (a former member, an invite link) doesn't make
	 * someone a member. Our own devices' messages (sync transcripts) are kept. A group whose members
	 * can't be learned right now (network) keeps its messages rather than losing real ones.
	 */
	async #dropNonMembers(generation: number, parsed: ParsedContent, sender: string, self: Self): Promise<void> {
		if (sender === self.aci) return;
		const contexts = new Map(parsed.groups.map((g) => [groupIdFromMasterKey(g.masterKey), g] as const));
		// A group context alone (no record, e.g. an empty DataMessage) is checked too: it would make us
		// fetch the group's state afterwards.
		const ids = new Set([...groupsNamed(parsed), ...contexts.keys()]);
		if (!ids.size) return;
		const allowed = new Set<string>();
		for (const id of ids) {
			const ctx = contexts.get(id);
			const verdict = await this.#senderInGroup(generation, id, ctx?.masterKey, ctx?.revision, sender);
			if (verdict !== "not a member") allowed.add(id);
			else this.#count("ignored:group message from a non-member");
		}
		keepGroups(parsed, allowed);
	}

	/**
	 * Fetches one group's state from the groups server and stores it, for the account of `generation`.
	 * Shares a fetch already in flight for it, unless that started before `notBefore`: then a new one
	 * follows. 403/404 (we aren't in the group any more) are stored as `fetchError`; other failures
	 * throw and leave the record as it was.
	 */
	#refreshGroup(g: GroupRecord, notBefore = 0, generation = this.#generation): Promise<GroupRecord> {
		const running = this.#groupRefreshes.get(g.id);
		if (running && running.generation === generation && running.startedAt >= notBefore) return running.promise;
		if (running) return running.promise.catch(() => undefined).then(() => this.#refreshGroup(g, notBefore, generation));
		const startedAt = Date.now();
		const promise = (async () => {
			this.#stillCurrent(generation);
			const dir = await this.#directoryFor(generation);
			let state: Partial<GroupRecord>;
			try {
				state = { ...(await fetchGroupState(fromBase64(g.masterKey), await this.#groupCredential())), fetchError: undefined };
			} catch (e) {
				if (!(e instanceof GroupFetchError && notAMember(e))) throw e;
				state = { fetchError: e.message, fetchedAt: Date.now() };
			}
			// Storage flags may have changed while we were fetching. Both refused once the account is forgotten.
			const next: GroupRecord = { ...((await dir.group(g.id)) ?? g), ...state };
			await dir.putGroup(next);
			return next;
		})().finally(() => {
			if (this.#groupRefreshes.get(g.id)?.promise === promise) this.#groupRefreshes.delete(g.id);
		});
		this.#groupRefreshes.set(g.id, { generation, startedAt, promise });
		return promise;
	}

	/** Today's group auth credential, fetching a week's worth when today's is missing. */
	async #groupCredential(): Promise<Credential> {
		const generation = this.#generation;
		const sealer = await this.#sealer();
		const blob = this.#get("group_credentials");
		let credentials: Credential[] = blob ? JSON.parse(dec.decode(await sealer.open("group_credentials", blob))) : [];
		let today = credentialForToday(credentials);
		if (!today) {
			const a = await this.#loadSecrets();
			credentials = await fetchCredentials(deviceAuth(a), a.aci, a.pni);
			const sealed = await sealer.seal("group_credentials", enc.encode(JSON.stringify(credentials)));
			// Fetched for an account forgotten meanwhile: the next account mustn't use (or keep) them.
			this.#stillCurrent(generation);
			this.#put("group_credentials", sealed);
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
		return this.#sealer().then((s) => new Directory(this.#accountDb, s));
	}

	/** The directory as work for `generation` may use it (refused once that account is forgotten). */
	#directoryFor(generation: number): Promise<Directory> {
		return this.#sealer().then((s) => new Directory(this.#databaseFor(generation), s));
	}

	/**
	 * Runs `fn` alone among protocol work. `generation`: when the caller started (read before its first
	 * await), so work started before a reset doesn't run for the account that replaced it.
	 */
	#withProtocolLock<T>(generation: number, fn: () => Promise<T>): Promise<T> {
		const guarded = () => {
			this.#stillCurrent(generation);
			return fn();
		};
		const run = this.#protocol.then(guarded, guarded);
		this.#protocol = run.catch(() => {});
		return run;
	}

	/** Throws when reset() ran since `generation` was read: the work belongs to a forgotten account. */
	#stillCurrent(generation: number): void {
		if (generation !== this.#generation) throw new AccountForgotten();
	}

	/** The database as work for `generation` may use it: refused once reset() has moved past it. */
	#databaseFor(generation: number): SqlDatabase {
		const db = this.#db;
		const check = () => this.#stillCurrent(generation);
		return {
			exec<T>(query: string, ...bindings: SqlValue[]): T[] {
				check();
				return db.exec<T>(query, ...bindings);
			},
			transaction<T>(fn: () => T): T {
				check();
				return db.transaction(fn);
			},
		};
	}

	/**
	 * Counters and errors kept across restarts. Not recorded while a reset is in progress; callers that
	 * may run for a forgotten account check their generation first (or their errors are AccountForgotten).
	 */
	#lasting(record: (c: Counters) => void): void {
		try {
			record(this.#counters());
		} catch (e) {
			if (!(e instanceof AccountForgotten)) throw e;
		}
	}

	#count(kind: string, n = 1): void {
		if (!n) return;
		this.#receive.kinds[kind] = (this.#receive.kinds[kind] ?? 0) + n;
		this.#lasting((c) => c.bump(kind, n));
	}

	#sendLog(): Promise<SendLog> {
		return this.#sealer().then((s) => new SendLog(this.#accountDb, s));
	}

	/** The message history (lower level than messages()/chats()). */
	messageStore(): Promise<MessageStore> {
		return this.#sealer().then((s) => new MessageStore(this.#accountDb, s));
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
		const generation = this.#generation;
		const retryLater = (key: string) => {
			if (generation === this.#generation) this.#putNumber(key, Date.now() + REFRESH_RETRY_MS);
		};
		try {
			if (!this.#receive.authFailed) await this.#connectChat().catch((e) => console.error("chat connect failed", e));
			pruneRetryState(this.#accountDb);
			// Undecryptable envelopes are kept for diagnosis, not forever: anyone can send them.
			this.#accountDb.exec("DELETE FROM failed_envelopes WHERE received_at < ?", Date.now() - FAILED_ENVELOPE_DAYS * 24 * 3600 * 1000);
			this.#accountDb.exec("DELETE FROM failed_envelopes WHERE id NOT IN (SELECT id FROM failed_envelopes ORDER BY id DESC LIMIT ?)", MAX_FAILED_ENVELOPES);
			if (Date.now() >= (this.#getNumber("next_key_refresh") ?? 0)) {
				await this.refreshKeys().catch((e) => {
					console.error("key refresh failed", e);
					retryLater("next_key_refresh");
				});
			}
			if (Date.now() >= (this.#getNumber("next_directory_sync") ?? 0)) {
				await this.syncDirectory().catch((e) => {
					console.error("directory sync failed", e);
					retryLater("next_directory_sync");
				});
			}
		} catch (e) {
			console.error("maintenance failed", e);
		}
		return this.#receive.authFailed ? undefined : Date.now() + WATCHDOG_MS;
	}

	async #refreshKeys(force: boolean): Promise<KeyRefreshResult> {
		const generation = this.#generation;
		const a = await this.#loadSecrets();
		const stores = await this.#loadStores();
		const result: KeyRefreshResult = {};
		for (const [ours, s] of Object.entries(stores) as [OurIdentity, ProtocolStore][]) {
			const server = await this.#keyCounts(a, ours);
			this.#stillCurrent(generation);
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
					if (generation !== this.#generation) throw e; // the keys went with the forgotten account
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
		this.#stillCurrent(generation);
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
			const generation = this.#generation;
			const a = await this.#loadSecrets();
			const sealer = await this.#sealer();
			const stores: Partial<Record<OurIdentity, ProtocolStore>> = {
				aci: await ProtocolStore.load(this.#databaseFor(generation), sealer, "aci", fromBase64(a.aciIdentityKeyPair), a.registrationId),
			};
			if (a.pniIdentityKeyPair && a.pniRegistrationId !== undefined) {
				stores.pni = await ProtocolStore.load(this.#databaseFor(generation), sealer, "pni", fromBase64(a.pniIdentityKeyPair), a.pniRegistrationId);
			}
			await this.#migrateLinkKeys(generation, a, stores);
			return stores;
		})().catch((e) => {
			this.#stores = undefined;
			throw e;
		});
		return this.#stores;
	}

	/** Moves the keys uploaded while linking (phase 2 kept them in the secrets blob) into the store. */
	async #migrateLinkKeys(generation: number, a: AccountSecrets, stores: Partial<Record<OurIdentity, ProtocolStore>>): Promise<void> {
		if (!a.signedPreKeys && !a.kyberLastResortPreKeys) return;
		for (const ours of ["aci", "pni"] as const) {
			const s = stores[ours];
			const signed = a.signedPreKeys?.[ours];
			const kyber = a.kyberLastResortPreKeys?.[ours];
			if (s && signed) await s.importKey("signed_prekeys", signed.id, fromBase64(signed.record), a.linkedAt);
			if (s && kyber) await s.importKey("kyber_prekeys", kyber.id, fromBase64(kyber.record), a.linkedAt);
		}
		const { signedPreKeys: _s, kyberLastResortPreKeys: _k, ...rest } = a;
		const sealed = await this.#sealSecrets(rest);
		this.#stillCurrent(generation);
		this.#put("account_secrets", sealed);
	}

	/** Proves the stored credentials work: GET /v1/accounts/whoami as this device. */
	async whoami(): Promise<unknown> {
		const a = await this.#loadSecrets();
		const res = await signalFetch(CHAT_HOST, "GET", "/v1/accounts/whoami", { headers: { Authorization: deviceAuth(a) } });
		return { status: res.status, body: tryJson(res.body) };
	}

	async #finishLink(envelope: Uint8Array, provisioningPrivateKey: Uint8Array, generation: number): Promise<void> {
		if (generation !== this.#generation) return;
		this.#setLink({ state: "linking" }, false);
		try {
			const msg = await decryptProvisionEnvelope(envelope, provisioningPrivateKey);
			await this.#socket?.close().catch(() => {});
			const secrets = await this.#register(msg);
			const sealed = await this.#sealSecrets(secrets);
			// Reset while the server was linking us: the device exists on the phone's list, but this
			// instance was told to forget everything, so it keeps nothing. Checked right before the
			// writes, with no await in between.
			this.#stillCurrent(generation);
			this.#put("account_secrets", sealed);
			this.#stores = undefined;
			this.#setLink({ state: "linked", aci: secrets.aci, pni: secrets.pni, number: secrets.number, deviceId: secrets.deviceId, linkedAt: secrets.linkedAt });
		} catch (e) {
			// Forgotten meanwhile: whatever state was set since (maybe a newer link) stays.
			if (generation !== this.#generation) return;
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
		const row = this.#accountDb.exec<{ value: ArrayBuffer | Uint8Array }>("SELECT value FROM kv WHERE key = ?", key)[0];
		return row && blob(row.value);
	}

	#put(key: string, value: Uint8Array): void {
		this.#accountDb.exec("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", key, value);
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
		// Transient states live in memory only; a restarted DO shows the last durable state. This row is
		// read before the storage key is (synchronously, in the constructor), so it isn't sealed and holds
		// no phone number: that stays in the sealed account secrets.
		if (persist && (link.state === "linked" || link.state === "error")) {
			const stored = link.state === "linked" ? { ...link, number: undefined } : link;
			this.#put("account_meta", enc.encode(JSON.stringify(stored)));
		}
	}

	#sealer(): Promise<Sealer> {
		this.#sealerPromise ??= Sealer.fromBase64(this.#opts.storageKey).catch((e) => {
			this.#sealerPromise = undefined;
			throw e;
		});
		return this.#sealerPromise;
	}

	async #sealSecrets(s: AccountSecrets): Promise<Uint8Array> {
		return (await this.#sealer()).seal("account_secrets", enc.encode(JSON.stringify(s)));
	}

	async #loadSecrets(): Promise<AccountSecrets> {
		const blob = this.#get("account_secrets");
		if (!blob) throw new Error("not linked");
		const a = JSON.parse(dec.decode(await (await this.#sealer()).open("account_secrets", blob))) as AccountSecrets;
		const l = this.#link;
		if (l.state === "linked" && l.aci === a.aci && l.number === undefined && a.number) this.#link = { ...l, number: a.number };
		return a;
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

/** The groups server's answer that we aren't in a group (as opposed to trouble reaching it). */
function notAMember(e: GroupFetchError): boolean {
	return e.status === 403 || e.status === 404;
}

/** Sets `key` (as the newest entry) and drops the oldest entries past MAX_TRACKED_GROUPS. */
function remember(map: Map<string, number>, key: string, value: number): void {
	map.delete(key);
	map.set(key, value);
	for (const k of map.keys()) {
		if (map.size <= MAX_TRACKED_GROUPS) break;
		map.delete(k);
	}
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
	const { masterKey: _m, members, endorsements: _e, ...rest } = g; // no keys or endorsements in tool output
	// Field by field: member records also hold profile keys.
	return { ...rest, members: members?.map((m) => ({ aci: m.aci, admin: m.admin, name: names.get(m.aci) })) };
}

/** A file to attach: forward a received attachment by "<message row id>/<index>", or new content. */
export type OutgoingFile =
	| { ref: string; caption?: string }
	| { fileName: string; contentType?: string; text: string; caption?: string }
	| { fileName?: string; contentType: string; base64: string; caption?: string };

/** A message ready to send: `body` as sent (shortened when long text went as an attachment). */
type Outgoing = {
	body: string;
	fullBody: string;
	pointers: Uint8Array[];
	stored: Attachment[];
	longText: boolean;
	/** @mentions in the body (DataMessage.bodyRanges, 18). */
	mentions: Mention[];
	/** DataMessage.quote (8) and its stored form. */
	quote?: { bytes: Uint8Array; record: NonNullable<MessageRecord["quote"]> };
	/** DataMessage.reaction (16) and its stored form; a reaction is sent on its own. */
	reaction?: { bytes: Uint8Array; record: NonNullable<MessageRecord["reaction"]> };
};

/** Reply to a message (quote it) or react to one, by the message's sentAt (the id MCP listings show). */
export type MessageExtras = { replyTo?: number; reaction?: { emoji: string; targetSentAt: number; remove?: boolean } };

/** Our copy of a sent message: the full text, and the files (with pointers, so get_attachment works). */
function outgoingRecord(conversation: string, a: AccountSecrets, sentAt: number, out: Outgoing, expiry: Expiry): MessageRecord {
	return {
		kind: out.reaction ? "reaction" : "message",
		...(out.reaction ? { reaction: out.reaction.record } : {}),
		...(out.quote ? { quote: out.quote.record } : {}),
		...(out.mentions.length ? { mentions: out.mentions } : {}),
		conversation,
		author: a.aci,
		authorDevice: a.deviceId,
		outgoing: true,
		sentAt,
		body: out.fullBody || undefined,
		expireTimer: expiry.expireTimer || undefined,
		...(out.stored.length ? { attachments: out.stored } : {}),
	};
}

/** Chat entry for a contact's new identity key (Signal's "safety number changed"). */
function identityChangeRecord(serviceId: string, device: number): MessageRecord {
	const now = Date.now();
	return { kind: "identity-change", conversation: `aci:${serviceId}`, author: serviceId, authorDevice: device, outgoing: false, sentAt: now };
}
