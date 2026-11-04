// Attachment download and decryption. Ported
// from Signal-Desktop ts/AttachmentCrypto.node.ts (decryptAttachmentV2) and
// ts/textsecure/WebAPI.preload.ts (getAttachment). The CDNs present certificates from Signal's
// own CA (checked 2026-11-03), so downloads go through signalFetch like everything else.

import { signalFetch } from "../net/http.js";
import { fromBase64 } from "../util/bytes.js";

/** Where an attachment lives and how to open it; kept (sealed) with the message record. */
export type AttachmentPointer = { cdnNumber: number; cdnKey?: string; cdnId?: string; key: string; digest?: string };

/** Desktop CDN hosts by cdnNumber (config/production.json). */
const CDN_HOSTS: Record<number, string> = { 0: "cdn.signal.org", 2: "cdn2.signal.org", 3: "cdn3.signal.org" };
const MAX_REDIRECTS = 3;

/** AttachmentPointer.cdnId is a fixed64: 8 little-endian bytes as the decoder keeps them. */
export function cdnIdFromFixed64(b: Uint8Array | undefined): string | undefined {
	if (b?.length !== 8) return undefined;
	const id = new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, true);
	return id ? id.toString() : undefined;
}

/** Downloads and decrypts one attachment; `size` is the plaintext length from the pointer. */
export async function downloadAttachment(p: AttachmentPointer, size: number | undefined): Promise<Uint8Array> {
	const host = CDN_HOSTS[p.cdnNumber];
	const name = p.cdnNumber === 0 ? p.cdnId : p.cdnKey;
	if (!host || !name) throw new Error(`attachment has no download location (cdn ${p.cdnNumber})`);
	let url = new URL(`https://${host}/attachments/${encodeURIComponent(name)}`);
	for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
		const res = url.hostname.endsWith(".signal.org") ? await signalGet(url) : await publicGet(url);
		if (res.status >= 300 && res.status < 400 && res.location) {
			url = new URL(res.location, url);
			continue;
		}
		if (res.status === 404) throw new Error("the attachment is no longer on Signal's servers (they expire after about 45 days)");
		if (res.status !== 200) throw new Error(`attachment download failed: HTTP ${res.status}`);
		return decryptAttachment(res.body, fromBase64(p.key), p.digest ? fromBase64(p.digest) : undefined, size);
	}
	throw new Error("attachment download: too many redirects");
}

async function signalGet(url: URL): Promise<{ status: number; location?: string; body: Uint8Array }> {
	const res = await signalFetch(url.hostname, "GET", url.pathname + url.search);
	return { status: res.status, location: res.headers.get("location") ?? undefined, body: res.body };
}

async function publicGet(url: URL): Promise<{ status: number; location?: string; body: Uint8Array }> {
	const res = await fetch(url, { redirect: "manual" });
	return { status: res.status, location: res.headers.get("location") ?? undefined, body: new Uint8Array(await res.arrayBuffer()) };
}

/**
 * iv (16) || AES-256-CBC ciphertext || HMAC-SHA256 (32), keys = aesKey (32) || macKey (32).
 * The MAC covers iv || ciphertext; the digest (when given) is SHA-256 of the whole blob. The
 * plaintext is padded before encryption, so it is cut to the pointer's size.
 */
export async function decryptAttachment(blob: Uint8Array, keys: Uint8Array, digest: Uint8Array | undefined, size: number | undefined): Promise<Uint8Array> {
	if (keys.length !== 64) throw new Error("attachment key must be 64 bytes");
	if (blob.length < 16 + 16 + 32) throw new Error("attachment too short");
	const macStart = blob.length - 32;
	const macKey = await crypto.subtle.importKey("raw", keys.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, blob.subarray(0, macStart)));
	if (!crypto.subtle.timingSafeEqual(mac, blob.subarray(macStart))) throw new Error("attachment MAC mismatch");
	if (digest) {
		const ours = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
		if (ours.length !== digest.length || !crypto.subtle.timingSafeEqual(ours, digest)) throw new Error("attachment digest mismatch");
	}
	const aesKey = await crypto.subtle.importKey("raw", keys.slice(0, 32), "AES-CBC", false, ["decrypt"]);
	const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv: blob.subarray(0, 16) }, aesKey, blob.subarray(16, macStart)));
	return size !== undefined && size <= plain.length ? plain.subarray(0, size) : plain;
}
