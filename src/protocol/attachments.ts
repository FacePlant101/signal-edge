// Attachment download and decryption, and
// encryption and upload for sending. Ported from Signal-Desktop ts/AttachmentCrypto.node.ts
// (decryptAttachmentV2, encryptAttachmentV2), ts/util/logPadSize.std.ts,
// ts/textsecure/WebAPI.preload.ts (getAttachment, getAttachmentUploadForm, putEncryptedAttachment)
// and ts/util/uploads/tusProtocol.node.ts; upload form from Signal-Server AttachmentControllerV4. The CDNs present certificates from Signal's
// own CA (checked 2026-11-03), so downloads go through signalFetch like everything else.
// Exception: a host behind Cloudflare (cdn3, where phones upload) can't be reached with
// cloudflare:sockets ("proxy request failed ... consider using fetch instead"), but a Worker's
// fetch() reaches it inside Cloudflare's network. The MAC and digest still authenticate the blob.

import { signalFetch } from "../net/http.js";
import { concat, dec, fromBase64, randomBytes, toBase64, timingSafeEqual } from "../util/bytes.js";
import type { Attachment, MessageRecord } from "./content.js";
import { encode } from "./proto.js";
import { CHAT_HOST } from "./socket.js";

/** Where an attachment lives and how to open it; kept (sealed) with the message record. */
export type AttachmentPointer = { cdnNumber: number; cdnKey?: string; cdnId?: string; key: string; digest?: string };

/** Desktop CDN hosts by cdnNumber (config/production.json). */
const CDN_HOSTS: Record<number, string> = { 0: "cdn.signal.org", 2: "cdn2.signal.org", 3: "cdn3.signal.org" };
const MAX_REDIRECTS = 3;
/** Hosts that refused a raw socket because they sit behind Cloudflare; downloads and uploads use fetch() from then on. */
const fetchOnlyHosts = new Set<string>();

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
		const res = url.hostname.endsWith(".signal.org") && !fetchOnlyHosts.has(url.hostname) ? await signalGetOrFetch(url) : await publicGet(url);
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

/** workerd's refusal to open a raw socket to a Cloudflare IP ("proxy request failed ... consider using fetch instead"). */
function refusesSockets(e: unknown): boolean {
	return /proxy request failed|consider using fetch/i.test(String(e));
}

/** signalGet, falling back to fetch() when the socket can't reach the host because Cloudflare fronts it. */
async function signalGetOrFetch(url: URL): Promise<{ status: number; location?: string; body: Uint8Array }> {
	try {
		return await signalGet(url);
	} catch (e) {
		if (!refusesSockets(e)) throw e;
		console.warn(`attachment download: ${url.hostname} refuses raw sockets (behind Cloudflare); using fetch()`);
		fetchOnlyHosts.add(url.hostname);
		return publicGet(url);
	}
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
	if (!timingSafeEqual(mac, blob.subarray(macStart))) throw new Error("attachment MAC mismatch");
	if (digest) {
		const ours = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
		if (ours.length !== digest.length || !timingSafeEqual(ours, digest)) throw new Error("attachment digest mismatch");
	}
	const aesKey = await crypto.subtle.importKey("raw", keys.slice(0, 32), "AES-CBC", false, ["decrypt"]);
	const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv: blob.subarray(0, 16) }, aesKey, blob.subarray(16, macStart)));
	return size !== undefined && size <= plain.length ? plain.subarray(0, size) : plain;
}

// --- sending ---

/** Desktop logPadSize: plaintext is zero-padded to one of these sizes before encryption. */
export function paddedSize(size: number): number {
	return Math.max(541, Math.floor(1.05 ** Math.ceil(Math.log(Math.max(size, 1)) / Math.log(1.05))));
}

/** Encrypts like decryptAttachment expects: iv || AES-256-CBC(padded) || HMAC, with fresh keys. */
export async function encryptAttachment(plaintext: Uint8Array): Promise<{ blob: Uint8Array; keys: Uint8Array; digest: Uint8Array }> {
	const keys = randomBytes(64);
	const iv = randomBytes(16);
	const padded = new Uint8Array(paddedSize(plaintext.length));
	padded.set(plaintext);
	const aesKey = await crypto.subtle.importKey("raw", keys.slice(0, 32), "AES-CBC", false, ["encrypt"]);
	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, padded)); // PKCS#7, as Desktop's cipher
	const macKey = await crypto.subtle.importKey("raw", keys.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const body = concat(iv, ct);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, body));
	const blob = concat(body, mac);
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
	return { blob, keys, digest };
}

/** Where an uploaded attachment went, plus what goes into its AttachmentPointer. */
export type UploadedAttachment = { cdnNumber: number; cdnKey: string; key: string; digest: string; size: number; uploadTimestamp: number };

type UploadForm = { cdn: number; key: string; headers: Record<string, string>; signedUploadLocation: string };

/** Encrypts `plaintext` and uploads it to the CDN the server picks (3: TUS, 2: Google resumable upload). */
export async function uploadAttachment(auth: string, plaintext: Uint8Array): Promise<UploadedAttachment> {
	const { blob, keys, digest } = await encryptAttachment(plaintext);
	const res = await signalFetch(CHAT_HOST, "GET", `/v4/attachments/form/upload?uploadLength=${blob.length}`, { headers: { Authorization: auth } });
	if (res.status === 413) throw new Error("attachment is larger than Signal accepts");
	if (res.status !== 200) throw new Error(`GET /v4/attachments/form/upload failed: HTTP ${res.status}`);
	const form = JSON.parse(dec.decode(res.body)) as UploadForm;
	if (form.cdn === 3) await tusUpload(form, blob);
	else if (form.cdn === 2) await resumableUpload(form, blob);
	else throw new Error(`upload form for unsupported cdn ${form.cdn}`);
	return { cdnNumber: form.cdn, cdnKey: form.key, key: toBase64(keys), digest: toBase64(digest), size: plaintext.length, uploadTimestamp: Date.now() };
}

/**
 * One request to an upload URL: Signal's own hosts over our TLS (Signal CA), others with fetch().
 * A *.signal.org host behind Cloudflare refuses cloudflare:sockets ("proxy request failed ... consider
 * using fetch instead", before anything is sent), so it falls back to fetch(), which reaches it inside
 * Cloudflare's network. The blob is encrypted and MAC'd either way.
 */
async function uploadRequest(url: URL, method: string, headers: Record<string, string>, body?: Uint8Array): Promise<{ status: number; header(name: string): string | undefined }> {
	if (url.hostname.endsWith(".signal.org") && !fetchOnlyHosts.has(url.hostname)) {
		try {
			const res = await signalFetch(url.hostname, method, url.pathname + url.search, { headers, body });
			return { status: res.status, header: (n) => res.headers.get(n) ?? undefined };
		} catch (e) {
			if (!refusesSockets(e)) throw e;
			console.warn(`attachment upload: ${url.hostname} refuses raw sockets (behind Cloudflare); using fetch()`);
			fetchOnlyHosts.add(url.hostname);
		}
	}
	const res = await fetch(url, { method, headers, body, redirect: "manual" });
	await res.arrayBuffer();
	return { status: res.status, header: (n) => res.headers.get(n) ?? undefined };
}

/** TUS 1.0 creation-with-upload (Desktop tusUpload); resumes once from the server's offset if cut short. */
async function tusUpload(form: UploadForm, blob: Uint8Array): Promise<void> {
	const endpoint = new URL(form.signedUploadLocation);
	// A dropped connection mid-body is the usual partial upload: fall through to the resume below.
	const res = await uploadRequest(endpoint, "POST", {
		...form.headers,
		"Tus-Resumable": "1.0.0",
		"Upload-Length": String(blob.length),
		"Upload-Metadata": `filename ${btoa(form.key)}`,
		"Content-Type": "application/offset+octet-stream",
	}, blob).catch((e: unknown) => ({ status: 0, error: e, header: (_n: string): string | undefined => undefined }));
	if ((res.status === 201 || res.status === 204) && Number(res.header("upload-offset") ?? blob.length) === blob.length) return;
	if (res.status >= 400 && res.status !== 409 && res.status !== 460 && res.status < 500) throw new Error(`attachment upload failed: HTTP ${res.status}`);
	const file = new URL(`${endpoint.pathname.replace(/\/$/, "")}/${encodeURIComponent(form.key)}`, endpoint);
	const head = await uploadRequest(file, "HEAD", { ...form.headers, "Tus-Resumable": "1.0.0" });
	const offset = Number(head.header("upload-offset"));
	if (head.status >= 300 || !Number.isInteger(offset) || offset < 0 || offset > blob.length) throw new Error(`attachment upload failed: HTTP ${res.status}, then HEAD ${head.status}`);
	if (offset === blob.length) return;
	const patch = await uploadRequest(file, "PATCH", { ...form.headers, "Tus-Resumable": "1.0.0", "Upload-Offset": String(offset), "Content-Type": "application/offset+octet-stream" }, blob.subarray(offset));
	if (patch.status !== 204 && patch.status !== 200) throw new Error(`attachment upload failed: PATCH HTTP ${patch.status}`);
}

/** CDN 2 (Desktop putEncryptedAttachment): POST the signed URL for a session, then PUT the bytes. */
async function resumableUpload(form: UploadForm, blob: Uint8Array): Promise<void> {
	const start = await uploadRequest(new URL(form.signedUploadLocation), "POST", form.headers);
	const location = start.header("location");
	if (start.status >= 300 || !location) throw new Error(`attachment upload: no upload session (HTTP ${start.status})`);
	const put = await uploadRequest(new URL(location), "PUT", { "Content-Range": `bytes 0-${blob.length - 1}/${blob.length}` }, blob);
	if (put.status !== 200 && put.status !== 201) throw new Error(`attachment upload failed: PUT HTTP ${put.status}`);
}

/** Desktop LONG_MESSAGE: text past the body limit goes as this attachment; clients show it as the body. */
export const LONG_TEXT_TYPE = "text/x-signal-plain";

/** SignalService.proto AttachmentPointer (cdnKey 15, cdnNumber 14, contentType 2, key 3, size 4, digest 6, fileName 7, flags 8, caption 11, uploadTimestamp 13, clientUuid 20). */
export function attachmentPointer(u: UploadedAttachment, meta: { contentType: string; fileName?: string; caption?: string; voiceNote?: boolean }): Uint8Array {
	return encode([
		[15, u.cdnKey],
		[14, u.cdnNumber],
		[2, meta.contentType],
		[3, fromBase64(u.key)],
		[4, u.size],
		[6, fromBase64(u.digest)],
		[7, meta.fileName],
		[8, meta.voiceNote ? 1 : undefined], // Flags.VOICE_MESSAGE
		[11, meta.caption],
		[13, u.uploadTimestamp],
		[20, randomBytes(16)],
	]);
}

/** The first bytes of `text` that fit in `max` UTF-8 bytes, without splitting a character. */
export function truncateUtf8(text: string, max: number): string {
	const bytes = new TextEncoder().encode(text);
	if (bytes.length <= max) return text;
	let end = max;
	while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end--;
	return dec.decode(bytes.subarray(0, end));
}

/**
 * Puts the full text of each record's long-text attachment (LONG_TEXT_TYPE, at most `maxBytes`) into
 * its body and drops that attachment, as Signal's apps show it. A record whose fetch fails keeps its
 * short body and the attachment, so it can still be fetched by reference.
 */
export async function expandLongText(
	records: MessageRecord[],
	maxBytes: number,
	fetch: (a: Attachment) => Promise<Uint8Array>,
): Promise<{ expanded: number; failed: number }> {
	let expanded = 0;
	let failed = 0;
	for (const rec of records) {
		const i = rec.attachments?.findIndex((a) => a.contentType === LONG_TEXT_TYPE && a.pointer) ?? -1;
		if (i < 0) continue;
		const a = rec.attachments![i]!;
		if (a.size !== undefined && a.size > maxBytes) continue;
		try {
			rec.body = dec.decode(await fetch(a));
			const rest = rec.attachments!.filter((_, j) => j !== i);
			if (rest.length) rec.attachments = rest;
			else delete rec.attachments;
			expanded++;
		} catch (e) {
			failed++;
			console.warn("long text attachment not fetched; keeping the short body", e);
		}
	}
	return { expanded, failed };
}
