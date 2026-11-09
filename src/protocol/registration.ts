/**
 * Registering a new primary account with a phone number, as Signal-Desktop's standalone registration
 * (nightly builds) does through libsignal-net: a verification session (captcha, then a code by SMS or
 * voice call), then POST /v1/registration. Wire formats from libsignal v0.9x `rust/net/chat/src/ws/
 * registration/request.rs` and its tests; status codes from `.../registration/error.rs`.
 */
import { signalFetch } from "../net/http.js";
import { dec, enc, randomBytes, toBase64 } from "../util/bytes.js";
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
	number: string;
	sessionId: string;
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
	/** Lets the account be registered again without SMS (derived from the account entropy pool). */
	recoveryPassword: Uint8Array;
	capabilities: Record<string, boolean>;
	discoverableByPhoneNumber: boolean;
};

export type RegisterAccountResponse = { aci: string; pni?: string; number?: string; storageCapable: boolean; reregistration: boolean };

const REGISTER_MESSAGES: Record<number, string> = {
	400: "the server rejected the request",
	401: "the verification session isn't verified (enter the code first)",
	403: "the server refused it",
	409: "the server offers a device transfer; it should have been skipped",
	423: "the number has a registration lock (a PIN set on another device); it can't be registered without that PIN",
	429: "too many attempts; wait and try again",
};

/** The JSON body of POST /v1/registration, as libsignal's register_account_request test has it. */
export function registrationBody(r: RegisterAccountRequest): Record<string, unknown> {
	return {
		sessionId: r.sessionId,
		accountAttributes: {
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
		},
		skipDeviceTransfer: true,
		aciIdentityKey: r.aciIdentityKey,
		pniIdentityKey: r.pniIdentityKey,
		aciSignedPreKey: r.aciSignedPreKey,
		pniSignedPreKey: r.pniSignedPreKey,
		aciPqLastResortPreKey: r.aciPqLastResortPreKey,
		pniPqLastResortPreKey: r.pniPqLastResortPreKey,
	};
}

/** POST /v1/registration with a verified session: creates (or takes over) the account for `number` as device 1. */
export async function registerAccount(r: RegisterAccountRequest): Promise<RegisterAccountResponse> {
	const res = await signalFetch(CHAT_HOST, "POST", "/v1/registration", {
		headers: { Authorization: `Basic ${btoa(`${r.number}:${r.password}`)}` },
		json: registrationBody(r),
	});
	if (res.status !== 200) {
		const retry = Number(res.headers.get("retry-after"));
		throw new RegistrationError(
			res.status,
			`POST /v1/registration: HTTP ${res.status}${REGISTER_MESSAGES[res.status] ? ` (${REGISTER_MESSAGES[res.status]})` : ""}`,
			undefined,
			Number.isFinite(retry) && retry > 0 ? retry : undefined,
		);
	}
	let body: { uuid?: unknown; pni?: string; number?: string; storageCapable?: boolean; reregistration?: boolean };
	try {
		body = JSON.parse(dec.decode(res.body));
	} catch {
		body = {};
	}
	// The server created the account, but without its id the credentials can't be used: say so plainly.
	if (typeof body.uuid !== "string") throw new Error("POST /v1/registration succeeded but its response couldn't be read (no account id); register again with a new code");
	return { aci: body.uuid.toLowerCase(), pni: body.pni?.toLowerCase(), number: body.number, storageCapable: !!body.storageCapable, reregistration: !!body.reregistration };
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
