// A minimal full ICE agent (RFC 8445) for one 1:1 call leg, compatible with WebRTC's: our only local
// candidate is the TURN relay, so a pair is (relay, remote candidate) and every check goes through
// the TURN connection. Checks, nomination (USE-CANDIDATE, or WebRTC's NOMINATION as controlled) and
// consent freshness (RFC 7675). One IceSession per remote device; they share the relay.

import { randomBytes } from "../util/bytes.js";
import {
	ATTR,
	CLASS,
	METHOD,
	addressKey,
	attr,
	attrString,
	checkFingerprint,
	checkIntegrity,
	encodeStun,
	newTransactionId,
	normalizeIp,
	parseIp,
	value,
	xorAddress,
	type Address,
	type ParsedStun,
} from "./stun.js";

export type IceParams = { ufrag: string; pwd: string };

export type Candidate = {
	foundation: string;
	component: number;
	protocol: string;
	priority: number;
	ip: string;
	port: number;
	type: string;
};

const ICE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function iceString(n: number): string {
	return Array.from(randomBytes(n), (b) => ICE_CHARS[b & 63]).join("");
}

/** Fresh credentials, sized as WebRTC makes them (4-char ufrag, 24-char password). */
export function newIceParams(): IceParams {
	return { ufrag: iceString(4), pwd: iceString(24) };
}

/** Parses an SDP candidate attribute ("candidate:..." with or without "a="). */
export function parseCandidate(sdp: string): Candidate | undefined {
	const m = /^(?:a=)?candidate:(\S+) (\d+) (\S+) (\d+) (\S+) (\d+) typ (\S+)/.exec(sdp.trim());
	if (!m) return undefined;
	const port = Number(m[6]);
	if (!(port > 0 && port < 65536)) return undefined;
	return { foundation: m[1]!, component: Number(m[2]), protocol: m[3]!.toLowerCase(), priority: Number(m[4]), ip: m[5]!, port, type: m[7]! };
}

/** Our relay candidate as WebRTC writes one; the related address is withheld as WebRTC does. */
export function relayCandidate(relay: Address, ufrag: string): string {
	return `candidate:${relayFoundation(relay)} 1 udp ${RELAY_PRIORITY} ${relay.ip} ${relay.port} typ relay raddr 0.0.0.0 rport 0 generation 0 ufrag ${ufrag} network-cost 10`;
}

function relayFoundation(relay: Address): number {
	let h = 0;
	for (const c of `relay|${relay.ip}`) h = (h * 31 + c.charCodeAt(0)) >>> 0;
	return h;
}

// RFC 8445 §5.1.2.1: (2^24)·type preference + (2^8)·local preference + (256 − component).
const RELAY_PRIORITY = (0 << 24) + (65535 << 8) + 255;
/** What a check's PRIORITY carries: the priority a peer-reflexive candidate of ours would have. */
const PRFLX_PRIORITY = ((110 << 24) >>> 0) + (65535 << 8) + 255;

const TICK_MS = 50;
/** Remote addresses per session: candidates and peer-reflexive sources are the peer's word. */
const MAX_PAIRS = 32;
const MAX_CHECK_ATTEMPTS = 10;
const CONSENT_INTERVAL_MS = 2_000;
const CONSENT_TIMEOUT_MS = 30_000;

type PairState = "waiting" | "in-progress" | "succeeded" | "failed";

type Pair = {
	remote: Address;
	priority: number;
	state: PairState;
	attempts: number;
	lastSent: number;
	/** The remote nominated this pair (controlled side) before our check on it succeeded. */
	nominatedByRemote?: boolean;
	/** We are nominating it (controlling side). */
	nominating?: boolean;
};

/** How an IceSession reaches the network: the shared TURN relay. */
export type IceTransport = {
	relay: Address;
	send(peer: Address, data: Uint8Array): Promise<void>;
	/** Opens the relay to `ip` (TURN CreatePermission); false if refused. */
	permit(ip: string): Promise<boolean>;
};

export type IceSessionOptions = {
	local: IceParams;
	remote: IceParams;
	controlling: boolean;
	tieBreaker: bigint;
	transport: IceTransport;
	/** The pair to send media on was chosen (and again whenever it changes). */
	onSelected(remote: Address): void;
	/** Every pair failed, or consent was lost. */
	onFailed(reason: string): void;
};

export class IceSession {
	readonly local: IceParams;
	readonly remote: IceParams;
	readonly controlling: boolean;
	/** Where media goes, once chosen. */
	selected?: Address;

	#opts: IceSessionOptions;
	#pairs = new Map<string, Pair>();
	#transactions = new Map<string, { pair: Pair; nominate: boolean }>();
	#timer?: ReturnType<typeof setInterval>;
	#closed = false;
	#lastHeard = 0;
	#lastConsent = 0;
	#family: 4 | 16;

	constructor(opts: IceSessionOptions) {
		this.#opts = opts;
		this.local = opts.local;
		this.remote = opts.remote;
		this.controlling = opts.controlling;
		this.#family = parseIp(opts.transport.relay.ip)?.length === 16 ? 16 : 4;
		this.#timer = setInterval(() => this.#tick(), TICK_MS);
	}

	get closed(): boolean {
		return this.#closed;
	}

	/** Adds a candidate the remote signaled. Only UDP in our relay's address family is reachable. */
	addRemoteCandidate(c: Candidate): void {
		if (this.#closed || c.component !== 1 || c.protocol !== "udp") return;
		const ip = normalizeIp(c.ip); // mDNS names (".local") and anything else unparsable are skipped
		if (!ip || parseIp(ip)!.length !== this.#family) return;
		this.#addPair({ ip, port: c.port }, c.priority);
	}

	/** True if `from` is (or was) a remote address of this session: media from it belongs here. */
	knows(from: Address): boolean {
		return this.#pairs.has(addressKey(from));
	}

	/** Does this STUN response answer one of our checks? */
	ownsResponse(m: ParsedStun): boolean {
		return this.#transactions.has(hex(m.txId));
	}

	/** Handles a STUN request (already routed here by its USERNAME) or response from `from`. */
	async handleStun(from: Address, m: ParsedStun): Promise<void> {
		if (this.#closed || !checkFingerprint(m)) return;
		if (m.method !== METHOD.BINDING) return;
		if (m.cls === CLASS.REQUEST) return this.#onRequest(from, m);
		if (m.cls === CLASS.SUCCESS || m.cls === CLASS.ERROR) return this.#onResponse(from, m);
	}

	close(): void {
		this.#closed = true;
		if (this.#timer !== undefined) clearInterval(this.#timer);
		this.#timer = undefined;
		this.#transactions.clear();
	}

	// --- incoming ---

	async #onRequest(from: Address, m: ParsedStun): Promise<void> {
		if (attrString(m, ATTR.USERNAME) !== `${this.local.ufrag}:${this.remote.ufrag}`) return;
		if (!(await checkIntegrity(m, enc(this.local.pwd)))) return;
		this.#heard();
		const res = await encodeStun(
			{ method: METHOD.BINDING, cls: CLASS.SUCCESS, txId: m.txId, attrs: [[ATTR.XOR_MAPPED_ADDRESS, xorAddress(from, m.txId)]] },
			{ integrityKey: enc(this.local.pwd), fingerprint: true },
		);
		void this.#opts.transport.send(from, res);

		// A check from an address we weren't told about: a peer-reflexive candidate (RFC 8445 §7.3.1.3).
		let pair = this.#pairs.get(addressKey(from));
		if (!pair) {
			const p = attr(m, ATTR.PRIORITY);
			pair = this.#addPair(from, p && p.length >= 4 ? new DataView(p.buffer, p.byteOffset).getUint32(0) : 0);
		}
		const nominated = attr(m, ATTR.USE_CANDIDATE) !== undefined || attr(m, ATTR.NOMINATION) !== undefined;
		if (!this.controlling && nominated) {
			if (pair.state === "succeeded") this.#select(pair);
			else pair.nominatedByRemote = true;
		}
		// Triggered check (§7.3.1.4): answer their check with ours right away.
		if (pair.state === "waiting" || pair.state === "failed") {
			pair.state = "waiting";
			pair.attempts = 0;
			void this.#check(pair, false);
		}
	}

	async #onResponse(from: Address, m: ParsedStun): Promise<void> {
		const id = hex(m.txId);
		const t = this.#transactions.get(id);
		if (!t) return;
		// The response must come from where the check went (§7.2.5.2.1).
		if (addressKey(from) !== addressKey(t.pair.remote)) return;
		if (!(await checkIntegrity(m, enc(this.remote.pwd)))) return;
		this.#transactions.delete(id);
		this.#heard();
		const pair = t.pair;
		if (m.cls === CLASS.ERROR) {
			// 487 role conflict and the like: we don't switch roles (RingRTC fixes them: caller controls).
			pair.state = "failed";
			return;
		}
		pair.state = "succeeded";
		if (this.controlling) {
			if (t.nominate) this.#select(pair);
			else if (!this.selected && !this.#nominating()) {
				pair.nominating = true;
				void this.#check(pair, true);
			}
		} else if (pair.nominatedByRemote) this.#select(pair);
	}

	// --- outgoing ---

	#addPair(remote: Address, priority: number): Pair {
		const key = addressKey(remote);
		const existing = this.#pairs.get(key);
		if (existing) return existing;
		if (this.#pairs.size >= MAX_PAIRS) return { remote, priority, state: "failed", attempts: 0, lastSent: 0 };
		const pair: Pair = { remote, priority, state: "waiting", attempts: 0, lastSent: 0 };
		this.#pairs.set(key, pair);
		void this.#opts.transport.permit(remote.ip).then((ok) => {
			if (!ok && pair.state !== "succeeded") pair.state = "failed";
		});
		return pair;
	}

	#nominating(): boolean {
		for (const p of this.#pairs.values()) if (p.nominating && p.state !== "failed") return true;
		return false;
	}

	#select(pair: Pair): void {
		if (this.selected && addressKey(this.selected) === addressKey(pair.remote)) return;
		this.selected = pair.remote;
		this.#lastConsent = Date.now();
		this.#opts.onSelected(pair.remote);
	}

	#heard(): void {
		this.#lastHeard = Date.now();
	}

	async #check(pair: Pair, nominate: boolean): Promise<void> {
		if (this.#closed) return;
		const txId = newTransactionId();
		this.#transactions.set(hex(txId), { pair, nominate });
		if (pair.state !== "succeeded") pair.state = "in-progress";
		pair.attempts++;
		pair.lastSent = Date.now();
		const attrs: [number, Uint8Array][] = [
			[ATTR.USERNAME, enc(`${this.remote.ufrag}:${this.local.ufrag}`)],
			[ATTR.PRIORITY, value.u32(PRFLX_PRIORITY)],
			[this.controlling ? ATTR.ICE_CONTROLLING : ATTR.ICE_CONTROLLED, value.tieBreaker(this.#opts.tieBreaker)],
		];
		if (nominate) attrs.push([ATTR.USE_CANDIDATE, new Uint8Array(0)]);
		const msg = await encodeStun({ method: METHOD.BINDING, cls: CLASS.REQUEST, txId, attrs }, { integrityKey: enc(this.remote.pwd), fingerprint: true });
		await this.#opts.transport.send(pair.remote, msg).catch(() => {});
	}

	#tick(): void {
		if (this.#closed) return;
		const now = Date.now();
		if (this.selected) {
			// Consent freshness: keep checking the selected pair; give up if nothing comes back.
			if (now - this.#lastConsent >= CONSENT_INTERVAL_MS) {
				this.#lastConsent = now;
				const pair = this.#pairs.get(addressKey(this.selected));
				if (pair) void this.#check(pair, this.controlling);
			}
			if (now - this.#lastHeard > CONSENT_TIMEOUT_MS) this.#fail("consent lost: no answer from the peer for 30 s");
			return;
		}
		// One check per tick (Ta), the best pair first: new pairs, then retransmissions with backoff.
		const pairs = [...this.#pairs.values()].sort((a, b) => b.priority - a.priority);
		for (const p of pairs) {
			if (p.state === "in-progress" && now - p.lastSent < Math.min(250 * 2 ** (p.attempts - 1), 2_000)) continue;
			if (p.state === "in-progress" && p.attempts >= MAX_CHECK_ATTEMPTS) {
				p.state = "failed";
				continue;
			}
			if (p.state === "succeeded" && p.nominating && now - p.lastSent >= 500) {
				if (p.attempts >= MAX_CHECK_ATTEMPTS * 2) p.nominating = false;
				else {
					void this.#check(p, true);
					return;
				}
			}
			if (p.state === "waiting" || p.state === "in-progress") {
				void this.#check(p, false);
				return;
			}
		}
	}

	#fail(reason: string): void {
		if (this.#closed) return;
		this.close();
		this.#opts.onFailed(reason);
	}
}

/** A random 64-bit ICE tie-breaker. */
export function newTieBreaker(): bigint {
	return new DataView(randomBytes(8).buffer).getBigUint64(0);
}

function enc(s: string): Uint8Array {
	return new TextEncoder().encode(s);
}

function hex(b: Uint8Array): string {
	return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
