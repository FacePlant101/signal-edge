/**
 * Registering a new primary account with a phone number, as Signal-Desktop's standalone registration
 * (nightly builds) does through libsignal-net: a verification session (captcha, then a code by SMS or
 * voice call), then POST /v1/registration. Wire formats from libsignal v0.9x `rust/net/chat/src/ws/
 * registration/request.rs` and its tests; status codes from `.../registration/error.rs`.
 *
 * The same POST /v1/registration also recovers an existing account by its ACI, proven with the
 * registration recovery password derived from its account entropy pool: Signal Login's "Account ID"
 * and "Account Key" (Signal-Server RegistrationController#recoverAccount).
 */
import { signalFetch } from "../net/http.js";
import { dec, enc, fromBase64, randomBytes, toBase64 } from "../util/bytes.js";
import { CHAT_HOST } from "./socket.js";

const SESSION_PATH = "/v1/verification/session";

/** A verification session as the server reports it. Times are absolute (ms since epoch), from its "seconds from now". */
export type VerificationSession = {
	id: string;
	/** A code may be requested now (the captcha was accepted). */
	allowedToRequestCode: boolean;
	/** The code was accepted: the account can be created. */
	verified: boolean;
	/** What the server still wants before it sends a code: "captcha" and/or "pushChallenge". */
	requestedInformation: string[];
	nextSmsAt?: number;
	nextCallAt?: number;
	nextVerificationAttemptAt?: number;
};

export type VerificationTransport = "sms" | "voice";

/** A refused registration step, with the session state the server sent along, if any. */
export class RegistrationError extends Error {
	constructor(
		readonly status: number,
		message: string,
		readonly session?: VerificationSession,
		/** Seconds the server asks us to wait (Retry-After), when it said. */
		readonly retryAfter?: number,
	) {
		super(message);
		this.name = "RegistrationError";
	}
}

type RawSession = {
	id: string;
	allowedToRequestCode?: boolean;
	verified?: boolean;
	requestedInformation?: string[];
	nextSms?: number;
	nextCall?: number;
	nextVerificationAttempt?: number;
};

function parseSession(body: Uint8Array, now = Date.now()): VerificationSession | undefined {
	let raw: RawSession;
	try {
		raw = JSON.parse(dec.decode(body)) as RawSession;
	} catch {
		return undefined;
	}
	if (typeof raw?.id !== "string") return undefined;
	const at = (secs: unknown) => (typeof secs === "number" && secs >= 0 ? now + secs * 1000 : undefined);
	return {
		id: raw.id,
		allowedToRequestCode: raw.allowedToRequestCode === true,
		verified: raw.verified === true,
		requestedInformation: Array.isArray(raw.requestedInformation) ? raw.requestedInformation.filter((x) => typeof x === "string") : [],
		nextSmsAt: at(raw.nextSms),
		nextCallAt: at(raw.nextCall),
		nextVerificationAttemptAt: at(raw.nextVerificationAttempt),
	};
}

function sessionPath(id: string, suffix = ""): string {
	return `${SESSION_PATH}/${encodeURIComponent(id)}${suffix}`;
}

const STATUS_MESSAGES: Record<number, string> = {
	400: "the server rejected the request",
	403: "the server refused it (wrong captcha or code?)",
	404: "the verification session expired or doesn't exist; start again",
	409: "not possible in this step (e.g. a code must be requested or entered first)",
	418: "the code could not be sent; try the other transport",
	422: "the phone number isn't valid",
	429: "too many attempts; wait and try again",
	440: "the SMS/voice provider couldn't deliver the code; try again later or the other transport",
};

async function sessionCall(what: string, method: string, path: string, json?: unknown, headers?: Record<string, string>): Promise<VerificationSession> {
	const res = await signalFetch(CHAT_HOST, method, path, { json, headers });
	const session = parseSession(res.body);
	if (res.status === 200 && session) return session;
	const retry = Number(res.headers.get("retry-after"));
	throw new RegistrationError(
		res.status,
		`${what}: HTTP ${res.status}${STATUS_MESSAGES[res.status] ? ` (${STATUS_MESSAGES[res.status]})` : ""}`,
		session,
		Number.isFinite(retry) && retry > 0 ? retry : undefined,
	);
}

/** POST /v1/verification/session for an E.164 number. The server asks for a captcha first. */
export async function createVerificationSession(number: string): Promise<VerificationSession> {
	if (!/^\+[1-9]\d{6,14}$/.test(number)) throw new Error("the number must be in E.164 form, e.g. +4712345678");
	return sessionCall("creating a verification session", "POST", SESSION_PATH, { number });
}

export async function getVerificationSession(id: string): Promise<VerificationSession> {
	return sessionCall("reading the verification session", "GET", sessionPath(id));
}

/**
 * The token from signalcaptchas.org (registration/generate.html): the text after "signalcaptcha://",
 * which is how the page hands it over; the prefix is stripped if pasted along.
 */
export async function submitCaptcha(id: string, captcha: string): Promise<VerificationSession> {
	const token = captcha.trim().replace(/^signalcaptcha:\/\//, "");
	if (!token) throw new Error("empty captcha token");
	return sessionCall("submitting the captcha", "PATCH", sessionPath(id), { captcha: token });
}

/** Asks the server to send a code by SMS or voice call. `languages` (Accept-Language) picks the message's language. */
export async function requestVerificationCode(id: string, transport: VerificationTransport, languages: string[] = []): Promise<VerificationSession> {
	const headers = languages.length ? { "Accept-Language": languages.join(",") } : undefined;
	// "desktop" as Desktop's standalone registration; the server uses it to pick the message template.
	return sessionCall("requesting a verification code", "POST", sessionPath(id, "/code"), { transport, client: "desktop" }, headers);
}

export async function submitVerificationCode(id: string, code: string): Promise<VerificationSession> {
	const digits = code.replace(/[\s-]/g, "");
	if (!/^\d{4,8}$/.test(digits)) throw new Error("the code is the digits from the SMS or call");
	return sessionCall("submitting the verification code", "PUT", sessionPath(id, "/code"), { code: digits });
}

/** A signed (EC or Kyber) prekey as /v1/registration and /v1/devices/link take it. */
export type UploadKey = { keyId: number; publicKey: string; signature: string };

export type RegisterAccountRequest = {
	/** The E.164 number being registered (with `sessionId`). Unused when recovering by `recoverAci`. */
	number?: string;
	/** A verified verification session: registering a phone number. */
	sessionId?: string;
	/**
	 * Recover the existing account with this ACI instead (Signal Login's "Account ID"), proven with
	 * `recoveryPassword`. Works for accounts with and without a phone number; the PNI keys are still
	 * required and are ignored for an account without one.
	 */
	recoverAci?: string;
	/** A TOTP code, when the account being recovered has TOTP two-factor authentication. */
	totp?: number;
	password: string;
	registrationId: number;
	pniRegistrationId: number;
	/** Serialized public keys (33 bytes, type 0x05), base64. */
	aciIdentityKey: string;
	pniIdentityKey: string;
	aciSignedPreKey: UploadKey;
	pniSignedPreKey: UploadKey;
	aciPqLastResortPreKey: UploadKey;
	pniPqLastResortPreKey: UploadKey;
	/** 16-byte unidentified-access key derived from our profile key. */
	unidentifiedAccessKey: Uint8Array;
	/** Lets the account be registered again without SMS (derived from the account entropy pool); also proves the account when recovering. */
	recoveryPassword: Uint8Array;
	capabilities: Record<string, boolean>;
	discoverableByPhoneNumber: boolean;
};

export type RegisterAccountResponse = {
	aci: string;
	/** Absent for an account without a phone number. */
	pni?: string;
	number?: string;
	storageCapable: boolean;
	reregistration: boolean;
	/** Accounts without a phone number: binds their group auth credentials (see receive_auth_credential_without_pni). */
	authCredentialSalt?: Uint8Array;
};

const REGISTER_MESSAGES: Record<number, string> = {
	400: "the server rejected the request",
	401: "the verification session isn't verified (enter the code first)",
	403: "the server refused it",
	409: "the server offers a device transfer; it should have been skipped",
	423: "the number has a registration lock (a PIN set on another device); it can't be registered without that PIN",
	429: "too many attempts; wait and try again",
};

const RECOVER_MESSAGES: Record<number, string> = {
	400: "the server rejected the request (is Signal Login enabled for this account?)",
	403: "the Account ID or Account Key is wrong, or there is no such account",
	409: "the server offers a device transfer; it should have been skipped",
	429: "too many attempts; wait and try again",
	441: "the account has two-factor authentication: give the TOTP code from the authenticator app",
};

/** accountAttributes as POST /v1/registration and PUT /v1/accounts/attributes take them (libsignal's AccountAttributes). */
export function accountAttributes(
	r: Pick<RegisterAccountRequest, "registrationId" | "capabilities" | "unidentifiedAccessKey" | "discoverableByPhoneNumber" | "recoveryPassword"> & {
		/** Absent for an account without a phone number (after registration). */
		pniRegistrationId?: number;
	},
): Record<string, unknown> {
	return {
		// No push service: messages are fetched over the authenticated socket.
		fetchesMessages: true,
		registrationId: r.registrationId,
		pniRegistrationId: r.pniRegistrationId,
		capabilities: r.capabilities,
		// A JSON array of bytes, not base64 (libsignal's AccountAttributes).
		unidentifiedAccessKey: [...r.unidentifiedAccessKey],
		unrestrictedUnidentifiedAccess: false,
		discoverableByPhoneNumber: r.discoverableByPhoneNumber,
		recoveryPassword: toBase64(r.recoveryPassword),
		registrationLock: null,
	};
}

/** The JSON body of POST /v1/registration, as libsignal's register_account_request test has it (plus recovery by ACI). */
export function registrationBody(r: RegisterAccountRequest): Record<string, unknown> {
	return {
		...(r.recoverAci
			? { recoveryPassword: toBase64(r.recoveryPassword), ...(r.totp !== undefined ? { totp: r.totp } : {}) }
			: { sessionId: r.sessionId }),
		accountAttributes: accountAttributes(r),
		skipDeviceTransfer: true,
		aciIdentityKey: r.aciIdentityKey,
		pniIdentityKey: r.pniIdentityKey,
		aciSignedPreKey: r.aciSignedPreKey,
		pniSignedPreKey: r.pniSignedPreKey,
		aciPqLastResortPreKey: r.aciPqLastResortPreKey,
		pniPqLastResortPreKey: r.pniPqLastResortPreKey,
	};
}

/**
 * POST /v1/registration: with a verified session, creates (or takes over) the account for `number`;
 * with `recoverAci`, recovers that account. Either way this device becomes its primary (device 1).
 */
export async function registerAccount(r: RegisterAccountRequest): Promise<RegisterAccountResponse> {
	if (!!r.recoverAci === !!r.sessionId) throw new Error("give either a verified sessionId (with number) or recoverAci");
	if (r.sessionId && !r.number) throw new Error("registering with a session needs the number");
	if (r.recoverAci && !ACI.test(r.recoverAci)) throw new Error("recoverAci must be an ACI (UUID)");
	const user = r.recoverAci ?? r.number!;
	const res = await signalFetch(CHAT_HOST, "POST", "/v1/registration", {
		headers: { Authorization: `Basic ${btoa(`${user}:${r.password}`)}` },
		json: registrationBody(r),
	});
	if (res.status !== 200) {
		const retry = Number(res.headers.get("retry-after"));
		const messages = r.recoverAci ? RECOVER_MESSAGES : REGISTER_MESSAGES;
		throw new RegistrationError(
			res.status,
			`POST /v1/registration: HTTP ${res.status}${messages[res.status] ? ` (${messages[res.status]})` : ""}`,
			undefined,
			Number.isFinite(retry) && retry > 0 ? retry : undefined,
		);
	}
	let body: { uuid?: unknown; pni?: string | null; number?: string | null; storageCapable?: boolean; reregistration?: boolean; authCredentialSalt?: unknown };
	try {
		body = JSON.parse(dec.decode(res.body));
	} catch {
		body = {};
	}
	// The server created the account, but without its id the credentials can't be used: say so plainly.
	if (typeof body.uuid !== "string") throw new Error("POST /v1/registration succeeded but its response couldn't be read (no account id); register again with a new code");
	return {
		aci: body.uuid.toLowerCase(),
		pni: body.pni?.toLowerCase() ?? undefined,
		number: body.number ?? undefined,
		storageCapable: !!body.storageCapable,
		reregistration: !!body.reregistration,
		authCredentialSalt: typeof body.authCredentialSalt === "string" && body.authCredentialSalt ? fromBase64(body.authCredentialSalt) : undefined,
	};
}

/** PUT /v1/accounts/attributes as the primary device (e.g. a restored profile key's unidentified-access key). */
export async function setAccountAttributes(chatAuth: string, attributes: Record<string, unknown>): Promise<void> {
	const res = await signalFetch(CHAT_HOST, "PUT", "/v1/accounts/attributes", { headers: { Authorization: chatAuth }, json: attributes });
	if (res.status !== 200 && res.status !== 204) throw new Error(`PUT /v1/accounts/attributes failed: HTTP ${res.status}`);
}

const ACI = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Signal Login's "Account ID": the account's ACI, shown in upper case; dashes, spaces and an "ACI:" prefix are optional. */
export function parseAccountId(input: string): string {
	const hex = input.trim().replace(/^aci:/i, "").replace(/[\s-]/g, "").toLowerCase();
	if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error("the Account ID is the account's ACI: 32 hexadecimal digits (dashes optional)");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Signal Login's "Account Key" (its account entropy pool): 64 characters of [0-9a-z]; case, spaces and dashes don't matter. */
export function parseAccountKey(input: string): string {
	const aep = input.trim().replace(/[\s-]/g, "").toLowerCase();
	if (!/^[0-9a-z]{64}$/.test(aep)) throw new Error("the Account Key has 64 letters and digits");
	return aep;
}

const AEP_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";
const AEP_LENGTH = 64;

/** A new account entropy pool: 64 characters from [0-9a-z], uniformly (libsignal AccountEntropyPool::generate). */
export function generateAccountEntropyPool(): string {
	let out = "";
	while (out.length < AEP_LENGTH) {
		for (const b of randomBytes(AEP_LENGTH)) {
			// Rejection sampling: bytes 252..255 are dropped, and each of the 36 characters gets exactly
			// 7 of the remaining 252 values (b / 7), so every character is equally likely.
			if (b < 252 && out.length < AEP_LENGTH) out += AEP_ALPHABET[Math.floor(b / 7)];
		}
	}
	return out;
}

/** HMAC-SHA256(masterKey, "Registration Recovery"): libsignal SvrKey::derive_registration_recovery_password. */
export async function registrationRecoveryPassword(masterKey: Uint8Array): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey("raw", masterKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode("Registration Recovery")));
}
