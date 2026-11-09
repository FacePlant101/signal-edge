// Decoders for incoming envelopes and their decrypted Content, reduced to the
// parts we store. Field numbers: Signal-Desktop protos/SignalService.proto.

import { toBase64 } from "../util/bytes.js";
import { cdnIdFromFixed64, type AttachmentPointer } from "./attachments.js";
import { Decoded } from "./proto.js";
import type { TimerSeen } from "./timers.js";
import { signal } from "./wasm.js";

export const ENVELOPE = { DOUBLE_RATCHET: 1, PREKEY_MESSAGE: 3, SERVER_DELIVERY_RECEIPT: 5, UNIDENTIFIED_SENDER: 6, PLAINTEXT_CONTENT: 8 } as const;
/** libsignal CiphertextMessageType, as returned for the inner message of sealed sender. */
export const CIPHERTEXT = { WHISPER: 2, PREKEY: 3, SENDER_KEY: 7, PLAINTEXT: 8 } as const;

export type Envelope = {
	type: number;
	sourceServiceId?: string;
	sourceDevice?: number;
	destinationServiceId?: string;
	clientTimestamp?: number;
	content?: Uint8Array;
	serverGuid?: string;
	serverTimestamp?: number;
	story: boolean;
};

export function uuidString(b: Uint8Array): string {
	const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
	return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/** Binary service id: 16-byte ACI, or 0x01 + 16 bytes for a PNI. */
function serviceIdFromBinary(b: Uint8Array | undefined): string | undefined {
	if (b?.length === 16) return uuidString(b);
	if (b?.length === 17 && b[0] === 1) return `PNI:${uuidString(b.subarray(1))}`;
	return undefined;
}

export function decodeEnvelope(buf: Uint8Array): Envelope {
	const m = new Decoded(buf);
	return {
		type: m.uint(1) ?? 0,
		sourceServiceId: m.string(11) ?? serviceIdFromBinary(m.bytes(19)),
		sourceDevice: m.uint(7),
		destinationServiceId: m.string(13) ?? serviceIdFromBinary(m.bytes(20)),
		clientTimestamp: m.uint(5),
		content: m.bytes(8),
		serverGuid: m.string(9) ?? (m.bytes(21)?.length === 16 ? uuidString(m.bytes(21)!) : undefined),
		serverTimestamp: m.uint(10),
		story: m.bool(16) ?? false,
	};
}

/** Signal pads plaintext with 0x80 followed by zeros (MessageReceiver #unpad). */
export function unpad(padded: Uint8Array): Uint8Array {
	for (let i = padded.length - 1; i >= 0; i--) {
		if (padded[i] === 0x80) return padded.subarray(0, i);
		if (padded[i] !== 0) throw new Error("invalid padding");
	}
	return padded;
}

/** Distribution id (UUID string) of a SenderKeyMessage or SenderKeyDistributionMessage: version byte, then a proto whose field 1 is the id. */
export function distributionId(message: Uint8Array, isSenderKeyMessage: boolean): string {
	// SenderKeyMessage carries a 64-byte signature after the proto.
	const proto = message.subarray(1, isSenderKeyMessage ? message.length - 64 : message.length);
	const id = new Decoded(proto).bytes(1);
	if (id?.length !== 16) throw new Error("sender key message without a distribution id");
	return uuidString(id);
}

export type Attachment = {
	contentType?: string;
	fileName?: string;
	size?: number;
	caption?: string;
	voiceNote?: boolean;
	width?: number;
	height?: number;
	/** CDN location and key, so the attachment can be fetched on request (src/signal/attachments.ts). */
	pointer?: AttachmentPointer;
};

/** One stored chat item, kept as JSON (sealed) in the messages table. */
export type MessageRecord = {
	kind: "message" | "edit" | "reaction" | "delete" | "identity-change";
	conversation: string; // "aci:<uuid>", "pni:<uuid>" or "group:<base64 id>"
	author: string; // sender ACI (our own ACI for messages sent from our other devices)
	authorDevice: number;
	outgoing: boolean;
	sentAt: number; // DataMessage timestamp, the id other messages refer to
	body?: string;
	attachments?: Attachment[];
	/**
	 * A quoted message, as the sender describes it. `verified`: the quoted id and author match a stored
	 * message in the same chat, and `text` is that message's text; false: no such stored message, so
	 * `text` is only the sender's word.
	 */
	quote?: { id?: number; author?: string; text?: string; mentions?: Mention[]; verified?: boolean };
	/** @mentions: each replaces a placeholder (U+FFFC) in the body; indices in UTF-16 code units. */
	mentions?: Mention[];
	reaction?: { emoji?: string; remove: boolean; targetAuthor?: string; targetSentAt?: number };
	targetSentAt?: number; // edits and deletes
	expireTimer?: number;
};

export type Mention = { start: number; length: number; aci: string };

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
/** A lowercase ACI (UUID). */
export const ACI_PATTERN = new RegExp(`^${UUID}$`);
const MENTION_TOKEN = new RegExp(`@\\[aci:(${UUID})\\]`, "gi");

/** The placeholder a mention stands on in the body (Signal's apps draw the name over it). */
export const MENTION_PLACEHOLDER = "\uFFFC";

/** BodyRange { start 1, length 2, mentionAci 3 | style 4 | mentionAciBinary 5 }: the mentions; text styles are dropped. */
export function parseMentions(ranges: unknown[] | undefined): Mention[] {
	const out: Mention[] = [];
	for (const buf of ranges ?? []) {
		if (!(buf instanceof Uint8Array)) continue;
		let r: Decoded;
		try {
			r = new Decoded(buf);
		} catch {
			continue; // a malformed range (text styles included) mustn't cost the whole message
		}
		const aci = (r.string(3) || serviceIdFromBinary(r.bytes(5)))?.toLowerCase();
		// Only ACIs can be mentioned; anything else (a PNI, junk) would show up, and be quoted back, as is.
		if (aci && ACI_PATTERN.test(aci)) out.push({ start: r.uint(1) ?? 0, length: r.uint(2) ?? 0, aci });
	}
	return out;
}

/**
 * The mentions that apply to `body`, in text order. A range past the text, or overlapping one already
 * kept, is dropped, and so is one that doesn't cover exactly the placeholder (real clients always put
 * a mention there; a range over ordinary words would only make text look addressed).
 */
export function validMentions(body: string, mentions: Mention[] | undefined): Mention[] {
	const out: Mention[] = [];
	let pos = 0;
	for (const m of [...(mentions ?? [])].sort((a, b) => a.start - b.start)) {
		if (m.start < pos || body.slice(m.start, m.start + m.length) !== MENTION_PLACEHOLDER) continue;
		out.push(m);
		pos = m.start + m.length;
	}
	return out;
}

/** The body with each mention's placeholder written as "@" + label(aci). */
export function showMentions(body: string, mentions: Mention[] | undefined, label: (aci: string) => string): string {
	let out = "";
	let pos = 0;
	for (const m of validMentions(body, mentions)) {
		out += body.slice(pos, m.start) + `@${label(m.aci)}`;
		pos = m.start + m.length;
	}
	return out + body.slice(pos);
}

/** Text with any literal "@[aci:<uuid>]" token written as "@(aci:<uuid>)", so echoing it into send_message mentions nobody. */
export function defuseMentionTokens(text: string): string {
	return text.replace(MENTION_TOKEN, "@(aci:$1)");
}

/**
 * Refuses mentions Signal's apps wouldn't send: any outside a group (`members` undefined: they offer
 * mentions only in groups, and a 1:1 client may show a bare placeholder box), and any of a non-member.
 */
export function checkMentions(mentions: Mention[], members: string[] | undefined): void {
	if (!mentions.length) return;
	if (!members) throw new Error("@mentions work only in group chats");
	const inGroup = new Set(members);
	const strangers = [...new Set(mentions.map((m) => m.aci).filter((aci) => !inGroup.has(aci)))];
	if (strangers.length) throw new Error(`not a member of this group, so can't be @mentioned: ${strangers.map((aci) => `aci:${aci}`).join(", ")}`);
}

/** Text an MCP client wrote with "@[aci:<uuid>]" tokens → the body with placeholders, and the mentions. */
export function extractMentions(text: string): { body: string; mentions: Mention[] } {
	const mentions: Mention[] = [];
	let body = "";
	let last = 0;
	for (const match of text.matchAll(MENTION_TOKEN)) {
		body += text.slice(last, match.index);
		mentions.push({ start: body.length, length: MENTION_PLACEHOLDER.length, aci: match[1]!.toLowerCase() });
		body += MENTION_PLACEHOLDER;
		last = match.index! + match[0].length;
	}
	return { body: body + text.slice(last), mentions };
}

export type ParsedContent = {
	records: MessageRecord[];
	senderKeyDistribution?: Uint8Array;
	/** A DecryptionErrorMessage: the sender couldn't decrypt one of our messages (src/signal/retry.ts). */
	decryptionError?: Uint8Array;
	/** What the content was, for counters: data, sync-sent, edit, receipt, typing, ... */
	kinds: string[];
	/** GroupContextV2 of group messages seen (master key and revision), to keep the group directory current. */
	groups: GroupContext[];
	/** Disappearing-message timers seen in plain messages and timer updates (src/signal/timers.ts). */
	timers: TimerSeen[];
};

export type GroupContext = { masterKey: Uint8Array; revision: number };

/**
 * Turns a decrypted Content into message records. `sender` is the decrypted sender's ACI;
 * sync "sent" transcripts from our own devices become outgoing records. A record belongs to a group
 * only through the group context inside the message (its master key), as in Signal's apps; the
 * sealed-sender layer's group id is chosen by the sender alone and isn't used for routing. Whether
 * the sender is a member is the caller's check (SignalClient does it before storing).
 */
export function parseContent(plaintext: Uint8Array, sender: string, senderDevice: number, ourAci: string): ParsedContent {
	const c = new Decoded(plaintext);
	const out: ParsedContent = { records: [], senderKeyDistribution: c.bytes(7), decryptionError: c.bytes(8), kinds: [], groups: [], timers: [] };

	const data = c.bytes(1);
	if (data) {
		out.kinds.push("data");
		const rec = dataMessage(data, sender, senderDevice, false, `aci:${sender}`, out.groups, out.timers);
		if (rec) out.records.push(rec);
		// Field numbers only (no content), so "data arrived but nothing stored" can be told apart.
		else out.kinds.push(`data-empty:${[...new Decoded(data).fields.keys()].sort((a, b) => a - b).join(",")}`);
	}

	const sync = c.bytes(2);
	if (sync) {
		const s = new Decoded(sync);
		const sent = s.bytes(1);
		if (sent && sender === ourAci) {
			out.kinds.push("sync-sent");
			const t = new Decoded(sent);
			// destinationServiceId (7), destinationServiceIdBinary (12), then destinationE164 (1)
			const dest = t.string(7) || serviceIdFromBinary(t.bytes(12)) || t.string(1);
			const destConv = dest ? (dest.startsWith("PNI:") ? `pni:${dest.slice(4)}` : dest.startsWith("+") ? `e164:${dest}` : `aci:${dest}`) : "unknown";
			const msg = t.bytes(3);
			if (msg) {
				const rec = dataMessage(msg, sender, senderDevice, true, destConv, out.groups, out.timers);
				if (rec) out.records.push(rec);
			}
			const edit = t.bytes(10);
			if (edit) {
				const rec = editMessage(edit, sender, senderDevice, true, destConv, out.groups);
				if (rec) out.records.push(rec);
			}
		} else {
			out.kinds.push(sent ? "sync-sent-from-other" : "sync-other");
		}
	}

	const edit = c.bytes(11);
	if (edit) {
		out.kinds.push("edit");
		const rec = editMessage(edit, sender, senderDevice, false, `aci:${sender}`, out.groups);
		if (rec) out.records.push(rec);
	}

	const others: [number, string][] = [[3, "call"], [4, "null"], [5, "receipt"], [6, "typing"], [8, "decryption-error"], [9, "story"], [10, "pni-signature"]];
	for (const [field, name] of others) if (c.fields.has(field)) out.kinds.push(name);
	if (out.senderKeyDistribution) out.kinds.push("sender-key-distribution");
	return out;
}

/** The group id of a `group:<id>` conversation, else undefined. */
export function groupOf(conversation: string): string | undefined {
	return conversation.startsWith("group:") ? conversation.slice(6) : undefined;
}

/** The groups a parsed Content names (by records and timers). */
export function groupsNamed(parsed: ParsedContent): Set<string> {
	return new Set([...parsed.records.map((r) => groupOf(r.conversation)), ...parsed.timers.map((t) => groupOf(t.conversation))].filter((x): x is string => !!x));
}

/** Drops records, timers and group contexts of groups not in `allowed`; everything outside groups stays. */
export function keepGroups(parsed: ParsedContent, allowed: Set<string>): void {
	const keep = (conversation: string) => {
		const id = groupOf(conversation);
		return !id || allowed.has(id);
	};
	parsed.records = parsed.records.filter((r) => keep(r.conversation));
	parsed.timers = parsed.timers.filter((t) => keep(t.conversation));
	parsed.groups = parsed.groups.filter((g) => allowed.has(toBase64(groupIdFromMasterKey(g.masterKey))));
}

function editMessage(buf: Uint8Array, author: string, device: number, outgoing: boolean, conversation: string, groups?: GroupContext[]): MessageRecord | undefined {
	const e = new Decoded(buf);
	const data = e.bytes(2);
	if (!data) return undefined;
	const rec = dataMessage(data, author, device, outgoing, conversation, groups);
	if (!rec) return undefined;
	return { ...rec, kind: "edit", targetSentAt: e.uint(1) };
}

function dataMessage(
	buf: Uint8Array,
	author: string,
	device: number,
	outgoing: boolean,
	conversation: string,
	groups?: GroupContext[],
	timers?: TimerSeen[],
): MessageRecord | undefined {
	const d = new Decoded(buf);
	const groupContext = d.bytes(15) && new Decoded(d.bytes(15)!);
	const masterKey = groupContext?.bytes(1);
	if (masterKey?.length === 32) groups?.push({ masterKey, revision: groupContext!.uint(2) ?? 0 });
	const groupId = masterKey?.length === 32 ? groupIdFromMasterKey(masterKey) : undefined;
	const rec: MessageRecord = {
		kind: "message",
		conversation: groupId ? `group:${toBase64(groupId)}` : conversation,
		author,
		authorDevice: device,
		outgoing,
		sentAt: d.uint(7) ?? 0,
		body: d.string(1),
		expireTimer: d.uint(5),
	};

	const attachments = (d.fields.get(2) ?? []).filter((v): v is Uint8Array => v instanceof Uint8Array).map(attachment);
	if (attachments.length) rec.attachments = attachments;

	const quote = d.bytes(8);
	if (quote) {
		const q = new Decoded(quote);
		rec.quote = { id: q.uint(1), author: q.string(5) ?? serviceIdFromBinary(q.bytes(8)), text: q.string(3) };
		const quoted = parseMentions(q.fields.get(6));
		if (quoted.length) rec.quote.mentions = quoted;
	}
	const mentions = parseMentions(d.fields.get(18));
	if (mentions.length) rec.mentions = mentions;

	const reaction = d.bytes(16);
	if (reaction) {
		const r = new Decoded(reaction);
		rec.kind = "reaction";
		rec.reaction = { emoji: r.string(1), remove: r.bool(2) ?? false, targetAuthor: r.string(4) ?? serviceIdFromBinary(r.bytes(6)), targetSentAt: r.uint(5) };
	}

	const del = d.bytes(17);
	if (del) {
		rec.kind = "delete";
		rec.targetSentAt = new Decoded(del).uint(1);
	}

	// Plain messages and timer updates (flags EXPIRATION_TIMER_UPDATE = 2) set the chat's timer, as in
	// Desktop handleDataMessage; reactions, deletes and profile-key updates don't.
	const shown = rec.kind !== "message" || rec.body !== undefined || !!rec.attachments || !!rec.quote;
	const timerUpdate = ((d.uint(4) ?? 0) & 2) === 2;
	// Stickers (11), shared contacts (9), payments (20) and gift badges (22) are messages too, though not shown here.
	const otherMessage = [9, 11, 20, 22].some((f) => d.fields.has(f));
	if (timers && (timerUpdate || (rec.kind === "message" && (shown || otherMessage)))) timers.push({ conversation: rec.conversation, expireTimer: d.uint(5) ?? 0, version: d.uint(23) });
	// Profile-key updates, expiration-timer changes etc. carry nothing to show.
	if (!shown) return undefined;
	return rec;
}

/** AttachmentPointer: cdnId=1 (fixed64) | cdnKey=15, contentType=2, key=3, size=4, digest=6, fileName=7, flags=8, width=9, height=10, caption=11, cdnNumber=14. */
function attachment(buf: Uint8Array): Attachment {
	const a = new Decoded(buf);
	const flags = a.uint(8) ?? 0;
	const key = a.bytes(3);
	const digest = a.bytes(6);
	const cdnKey = a.string(15);
	const cdnId = cdnIdFromFixed64(a.bytes(1));
	return {
		contentType: a.string(2),
		fileName: a.string(7),
		size: a.uint(4),
		caption: a.string(11),
		voiceNote: (flags & 1) === 1 || undefined,
		width: a.uint(9),
		height: a.uint(10),
		pointer: key?.length === 64 && (cdnKey || cdnId) ? { cdnNumber: a.uint(14) ?? 0, cdnKey, cdnId, key: toBase64(key), digest: digest && toBase64(digest) } : undefined,
	};
}

function groupIdFromMasterKey(masterKey: Uint8Array): Uint8Array {
	const sig = signal();
	return sig.WasmGroupMasterKey.from_bytes(masterKey).derive_identifier().serialize;
}
