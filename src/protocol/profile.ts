/**
 * Our own profile (PUT /v1/profile, Signal-Server ProfileController#setProfile): the name others see.
 * Encryption as Signal-Desktop ts/Crypto.node.ts (encryptProfile, encryptProfileItemWithPadding,
 * PaddedLengths) and ts/util/encryptProfileData.preload.ts; version and commitment from zkgroup.
 * Others fetch the profile with the profile key our messages carry, so they see the name without
 * anything else being sent.
 */
import { signalFetch } from "../net/http.js";
import { concat, dec, enc, fromBase64, randomBytes, toBase64 } from "../util/bytes.js";
import { libsignalExtra } from "./sealed.js";
import { CHAT_HOST } from "./socket.js";

/** Desktop PaddedLengths.Name: the server takes exactly these (81 and 285 bytes once encrypted). */
export const PROFILE_NAME_PADDED_LENGTHS = [53, 257] as const;
const IV_LENGTH = 12;

/** Desktop encryptProfile: AES-256-GCM under the profile key, the random 12-byte IV first. */
export async function encryptProfileItem(data: Uint8Array, profileKey: Uint8Array): Promise<Uint8Array> {
	if (profileKey.length !== 32) throw new Error("profile key must be 32 bytes");
	const iv = randomBytes(IV_LENGTH);
	const key = await crypto.subtle.importKey("raw", profileKey, "AES-GCM", false, ["encrypt"]);
	return concat(iv, new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data)));
}

/** Desktop decryptProfile. */
export async function decryptProfileItem(data: Uint8Array, profileKey: Uint8Array): Promise<Uint8Array> {
	if (data.length < IV_LENGTH + 16 + 1) throw new Error("encrypted profile item too short");
	const key = await crypto.subtle.importKey("raw", profileKey, "AES-GCM", false, ["decrypt"]);
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.subarray(0, IV_LENGTH) }, key, data.subarray(IV_LENGTH)));
}

/** A profile name: given name, and a family name if any. */
export type ProfileName = { given: string; family?: string };

/** Checks and trims a name: a given name is required; neither part may contain NUL; together at most 257 bytes. */
export function checkProfileName(name: ProfileName): ProfileName {
	const given = name.given.trim();
	const family = name.family?.trim() || undefined;
	if (!given) throw new Error("a profile name needs a given name");
	if (given.includes("\0") || family?.includes("\0")) throw new Error("a profile name can't contain NUL characters");
	const bytes = enc.encode(family ? `${given}\0${family}` : given).length;
	if (bytes > PROFILE_NAME_PADDED_LENGTHS[1]) throw new Error(`the profile name is ${bytes} bytes; at most ${PROFILE_NAME_PADDED_LENGTHS[1]}`);
	return { given, family };
}

/** Desktop: "given\0family", zero-padded to 53 or 257 bytes, then encrypted. */
export async function encryptProfileName(name: ProfileName, profileKey: Uint8Array): Promise<Uint8Array> {
	const { given, family } = checkProfileName(name);
	const plain = enc.encode(family ? `${given}\0${family}` : given);
	const length = PROFILE_NAME_PADDED_LENGTHS.find((l) => plain.length <= l)!;
	const padded = new Uint8Array(length);
	padded.set(plain);
	return encryptProfileItem(padded, profileKey);
}

/** Desktop decryptProfileName: the given name up to the first NUL, the family name up to the next. */
export async function decryptProfileName(data: Uint8Array, profileKey: Uint8Array): Promise<ProfileName> {
	const padded = await decryptProfileItem(data, profileKey);
	const parts = dec.decode(padded).split("\0");
	return { given: parts[0] ?? "", family: parts[1] || undefined };
}

/** The JSON body of PUT /v1/profile for a name (no avatar, about text, badges or payment address). */
export async function profileRequestBody(profileKey: Uint8Array, aci: string, name: ProfileName): Promise<Record<string, unknown>> {
	const x = libsignalExtra();
	return {
		version: x.profile_key_version(profileKey, aci),
		name: toBase64(await encryptProfileName(name, profileKey)),
		about: null,
		aboutEmoji: null,
		badgeIds: [],
		paymentAddress: null,
		avatar: false,
		sameAvatar: false,
		commitment: toBase64(x.profile_key_commitment(profileKey, aci)),
		// Phone-number sharing: off (a one-byte item, as Desktop sends it).
		phoneNumberSharing: toBase64(await encryptProfileItem(new Uint8Array([0]), profileKey)),
	};
}

const PROFILE_MESSAGES: Record<number, string> = {
	400: "the server rejected the profile",
	401: "the account's credentials weren't accepted",
	412: "the account has the profiles_v2 capability (another device of it uses the newer profile format)",
	422: "the server found the profile request malformed",
};

/** PUT /v1/profile with our device credentials. */
export async function setProfile(chatAuth: string, body: Record<string, unknown>): Promise<void> {
	const res = await signalFetch(CHAT_HOST, "PUT", "/v1/profile", { headers: { Authorization: chatAuth }, json: body });
	if (res.status !== 200) {
		const why = PROFILE_MESSAGES[res.status];
		throw new Error(`PUT /v1/profile failed: HTTP ${res.status}${why ? ` (${why})` : ""} ${dec.decode(res.body).slice(0, 200)}`.trim());
	}
}

/** For tests: decodes a profile request's encrypted name. */
export async function profileRequestName(body: Record<string, unknown>, profileKey: Uint8Array): Promise<ProfileName> {
	return decryptProfileName(fromBase64(String(body.name)), profileKey);
}
