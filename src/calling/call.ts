// 1:1 voice calls with Signal's apps, speaking RingRTC's protocol (ringrtc core/call_fsm.rs,
// connection.rs; webrtc ringrtc/rffi/src/peer_connection.cc for the media parameters):
//
//   signaling   CallMessage offer/answer/ICE/hangup/busy over the normal message path (urgent)
//   transport   one TURN allocation over TCP; ICE checks through it to each answering device
//   media       SRTP AEAD_AES_256_GCM with keys from the signaled X25519 keys and both identity keys;
//               Opus (PT 102, 48 kHz) on SSRC 1002 (caller) / 2002 (callee)
//   control     RingRTC's RTP data channel (PT 101, SSRC 0xD): Accepted, Hangup, SenderStatus
//
// Outgoing: the offer goes to every device of the callee; each device answers while it rings and
// gets its own leg (ICE session + SRTP keys); the first to send Accepted over RTP data wins, and the
// others are told "accepted on another device". Incoming: a single leg to the calling device, which
// controls ICE; accept() answers, and Accepted goes out over RTP data once ICE connects.

import { signal } from "../protocol/wasm.js";
import { randomBytes } from "../util/bytes.js";
import { IceSession, newIceParams, newTieBreaker, parseCandidate, relayCandidate, type IceParams } from "./ice.js";
import { OPUS_CLOCK, OPUS_PT, RTP_DATA_PT, RTP_DATA_SSRC, audioSsrc, buildRtp, isRtcp, isRtpOrRtcp, opusSamples, parseRtp } from "./rtp.js";
import {
	HANGUP_TYPE,
	OFFER_TYPE,
	VIDEO_CODEC,
	decodeIceCandidate,
	decodeOfferOrAnswer,
	decodeRtpData,
	encodeIceCandidate,
	encodeOfferOrAnswer,
	encodeRtpData,
	negotiateSrtpKeys,
	type CallMessage,
	type ConnectionParametersV4,
	type RtpDataMessage,
} from "./signaling.js";
import { SrtpSession } from "./srtp.js";
import { ATTR, CLASS, attrString, decodeStun, isStun, type Address } from "./stun.js";
import { TurnClient, turnServers, type IceServerGroup } from "./turn.js";

/** Outgoing: calling → ringing (a device of theirs is reachable) → connected. Incoming: ringing → connecting (accepted) → connected. */
export type CallState = "calling" | "ringing" | "connecting" | "connected" | "ended";

export type CallEndReason =
	/** We hung up (or declined). */
	| "hangup"
	| "remote-hangup"
	| "declined"
	| "busy"
	| "need-permission"
	/** Nobody answered (outgoing), or we didn't (incoming), within RING_TIMEOUT_MS. */
	| "timeout"
	/** Incoming: another device of ours answered, declined or was busy. */
	| "accepted-elsewhere"
	| "declined-elsewhere"
	| "busy-elsewhere"
	/** No route (TURN, ICE) or the connection was lost. */
	| "failed";

/** One received Opus packet. `timestamp` is the RTP timestamp (48 kHz). */
export type AudioPacket = { opus: Uint8Array; timestamp: number; sequence: number };

/** An Opus codec (48 kHz, mono) for the PCM helpers; bring your own (e.g. a libopus WASM build). */
export interface OpusCodec {
	/** One frame of 48 kHz mono PCM (2.5–60 ms; sendPcm uses 20 ms = 960 samples) → one Opus packet. */
	encode(pcm: Int16Array): Uint8Array;
	/** One Opus packet → 48 kHz mono PCM. */
	decode(packet: Uint8Array): Int16Array;
	free?(): void;
}

export type CallOptions = {
	/** Makes an Opus codec for this call, enabling sendPcm() and onPcm. */
	codec?: () => OpusCodec | Promise<OpusCodec>;
};

/** What a call needs from the account (SignalClient provides it). */
export type CallHost = {
	ourAci: string;
	ourDeviceId: number;
	/** Our ACI identity public key (33 bytes). */
	ourIdentityKey: Uint8Array;
	/** The peer's identity public key (33 bytes), as recorded from our session with them. */
	peerIdentityKey(aci: string): Promise<Uint8Array | undefined>;
	/** Sends a CallMessage to every device of `aci` (the message's destinationDeviceId picks one). */
	send(aci: string, message: CallMessage, urgent: boolean): Promise<void>;
	/** GET /v2/calling/relays. */
	iceServers(): Promise<IceServerGroup[]>;
};

/** RingRTC TIME_OUT_PERIOD / MAX_MESSAGE_AGE. */
export const RING_TIMEOUT_MS = 60_000;
export const MAX_OFFER_AGE_MS = 60_000;
const CONNECT_TIMEOUT_MS = 30_000;
/** RingRTC resends the latest RTP data message every second (SEND_RTP_DATA_MESSAGE_INTERVAL_MILLIS). */
const RTP_DATA_INTERVAL_MS = 1_000;
/** Our receive cap, which bounds what they send us (video we'd drop, mostly). */
const MAX_BITRATE_BPS = 100_000n;
/** How much audio sendAudio() may queue ahead of real time. */
const MAX_QUEUED_MS = 60_000;
const PCM_FRAME = 960; // 20 ms
/** Devices answering one outgoing call that we keep a leg for (Signal allows a handful per account). */
const MAX_LEGS = 8;

/** One device's connection: ICE to it and the SRTP keys agreed with it. */
class Leg {
	ice!: IceSession;
	tx!: SrtpSession;
	rx!: SrtpSession;
	/** Candidates signaled before the answer (or before accept()). */
	pending: string[] = [];
	/** Its answer arrived (and is being set up). */
	answered = false;
	dataCounter = 0;
	sends: Promise<unknown> = Promise.resolve();
	constructor(readonly device: number) {}
}

export class SignalCall {
	readonly id: bigint;
	/** The other party's ACI. */
	readonly peer: string;
	readonly direction: "outgoing" | "incoming";
	/** Incoming: they offered video (we answer, and drop any video they send). */
	readonly video: boolean;
	state: CallState;
	endReason?: CallEndReason;
	/** Resolves when the call ends. */
	readonly ended: Promise<CallEndReason>;

	onState?: (state: CallState, call: SignalCall) => void;
	/** Opus packets from the other side, once connected. */
	onAudio?: (packet: AudioPacket, call: SignalCall) => void;
	/** Decoded audio (48 kHz mono), when the call has a codec. */
	onPcm?: (pcm: Int16Array, call: SignalCall) => void;

	#host: CallHost;
	#opts: CallOptions;
	#onFinished: (call: SignalCall) => void;
	#resolveEnded!: (r: CallEndReason) => void;
	#turn?: TurnClient;
	#ice: IceParams = newIceParams();
	#tieBreaker = newTieBreaker();
	#privateKey: Uint8Array;
	#publicKey: Uint8Array;
	#legs = new Map<number, Leg>();
	#active?: Leg;
	#timers = new Set<ReturnType<typeof setTimeout>>();
	#dataTimer?: ReturnType<typeof setInterval>;
	#codec?: OpusCodec;
	/** Incoming: the caller's device and its offer. */
	#callerDevice?: number;
	#offer?: ConnectionParametersV4;
	#accepted = false;
	#dataMessage: RtpDataMessage = {};

	// Outgoing audio.
	#queue: Uint8Array[] = [];
	#queuedSamples = 0;
	#pacer?: ReturnType<typeof setTimeout>;
	#seq = randomU16();
	#ts = randomU32();
	#tsAt = 0;
	#nextAt = 0;
	#pcm = new Int16Array(0);

	private constructor(host: CallHost, opts: CallOptions, onFinished: (c: SignalCall) => void, init: { id: bigint; peer: string; direction: "outgoing" | "incoming"; video: boolean; state: CallState }) {
		this.#host = host;
		this.#opts = opts;
		this.#onFinished = onFinished;
		this.id = init.id;
		this.peer = init.peer;
		this.direction = init.direction;
		this.video = init.video;
		this.state = init.state;
		this.ended = new Promise((r) => (this.#resolveEnded = r));
		const priv = signal().WasmPrivateKey.generate();
		this.#privateKey = priv.serialize();
		this.#publicKey = priv.getPublicKey().serialize().subarray(1);
		priv.free?.();
	}

	/** @internal Places a call: allocates the relay, then offers to every device of `peer`. */
	static async outgoing(host: CallHost, peer: string, opts: CallOptions, hooks: { onCreated(c: SignalCall): void; onFinished(c: SignalCall): void }): Promise<SignalCall> {
		const call = new SignalCall(host, opts, hooks.onFinished, { id: randomCallId(), peer, direction: "outgoing", video: false, state: "calling" });
		// Registered before the offer goes out: an answer can arrive before send() returns.
		hooks.onCreated(call);
		try {
			await call.#setup();
			await host.send(peer, { offer: { id: call.id, type: OFFER_TYPE.AUDIO, opaque: encodeOfferOrAnswer(call.#localParams()) } }, true);
			await call.#sendCandidate(undefined);
		} catch (e) {
			call.#end("failed");
			throw e;
		}
		call.#after(RING_TIMEOUT_MS, () => {
			if (call.state !== "connected") void call.#hangupAndEnd("timeout");
		});
		return call;
	}

	/** @internal An offer arrived; the app accepts or declines. */
	static incoming(host: CallHost, peer: string, device: number, id: bigint, video: boolean, offer: ConnectionParametersV4, opts: CallOptions, onFinished: (c: SignalCall) => void): SignalCall {
		const call = new SignalCall(host, opts, onFinished, { id, peer, direction: "incoming", video, state: "ringing" });
		call.#callerDevice = device;
		call.#offer = offer;
		call.#legs.set(device, new Leg(device));
		call.#after(RING_TIMEOUT_MS, () => {
			if (!call.#accepted) call.#end("timeout");
		});
		return call;
	}

	/** Incoming: answers. Resolves once the answer is sent; the state turns "connected" when media flows. */
	async accept(): Promise<void> {
		if (this.direction !== "incoming" || this.#accepted || this.state === "ended") return;
		this.#accepted = true;
		this.#setState("connecting");
		const device = this.#callerDevice!;
		const leg = this.#legs.get(device)!;
		try {
			await this.#setup();
			if (this.#isEnded()) return;
			await this.#startLeg(leg, this.#offer!);
			await this.#host.send(this.peer, { answer: { id: this.id, opaque: encodeOfferOrAnswer(this.#localParams()) }, destinationDeviceId: device }, false);
			await this.#sendCandidate(device);
		} catch (e) {
			void this.#hangupAndEnd("failed");
			throw e;
		}
		this.#after(CONNECT_TIMEOUT_MS, () => {
			if (this.state !== "connected") void this.#hangupAndEnd("failed");
		});
	}

	/** Incoming: declines (the caller sees it declined). */
	async decline(): Promise<void> {
		if (this.direction !== "incoming" || this.state === "ended") return;
		await this.#hangupAndEnd("hangup");
	}

	/** Ends the call (or cancels it while it rings). */
	async hangup(): Promise<void> {
		if (this.state === "ended") return;
		await this.#hangupAndEnd("hangup");
	}

	/**
	 * Queues one Opus packet (48 kHz, mono, any frame size up to 120 ms) to send. Packets go out paced
	 * at real time, so a whole clip can be queued at once; audio queued before the call connects is
	 * held until it does.
	 */
	sendAudio(opus: Uint8Array): void {
		if (this.state === "ended") return;
		const samples = opusSamples(opus);
		if (!samples) throw new Error("sendAudio: not an Opus packet");
		this.#queue.push(opus);
		this.#queuedSamples += samples;
		while (this.#queuedSamples > (MAX_QUEUED_MS * OPUS_CLOCK) / 1000 && this.#queue.length > 1) this.#queuedSamples -= opusSamples(this.#queue.shift()!);
		this.#pump();
	}

	/** Sends 48 kHz mono PCM through the call's codec (any length; buffered into 20 ms frames). */
	sendPcm(pcm: Int16Array): void {
		if (!this.#codec) throw new Error("sendPcm: the call has no codec (CallOptions.codec)");
		if (this.state === "ended") return;
		const all = new Int16Array(this.#pcm.length + pcm.length);
		all.set(this.#pcm);
		all.set(pcm, this.#pcm.length);
		let off = 0;
		for (; off + PCM_FRAME <= all.length; off += PCM_FRAME) this.sendAudio(this.#codec.encode(all.subarray(off, off + PCM_FRAME)));
		this.#pcm = all.slice(off);
	}

	/** Drops queued audio that hasn't gone out yet (e.g. the other side started talking). */
	clearAudio(): void {
		this.#queue = [];
		this.#queuedSamples = 0;
		this.#pcm = new Int16Array(0);
	}

	/** Milliseconds of audio queued and not yet sent. */
	get queuedMs(): number {
		return (this.#queuedSamples * 1000) / OPUS_CLOCK;
	}

	/** The device the call is connected to (outgoing: the one that answered). */
	get remoteDevice(): number | undefined {
		return this.#active?.device ?? this.#callerDevice;
	}

	// --- signaling in ---

	/** @internal A CallMessage for this call from `device` of the peer. */
	async handleMessage(device: number, m: CallMessage): Promise<void> {
		if (this.state === "ended") return;
		if (m.answer && m.answer.id === this.id && this.direction === "outgoing") await this.#onAnswer(device, m.answer.opaque);
		for (const u of m.iceUpdates ?? []) {
			if (u.id !== this.id) continue;
			const sdp = decodeIceCandidate(u.opaque);
			if (sdp) this.#onCandidate(device, sdp);
		}
		if (m.hangup && m.hangup.id === this.id) await this.#onHangup(device, m.hangup.type, m.hangup.deviceId);
		if (m.busy && m.busy.id === this.id) await this.#onBusy(device);
	}

	async #onAnswer(device: number, opaque: Uint8Array): Promise<void> {
		const existing = this.#legs.get(device);
		if (existing?.ice || existing?.answered || this.#active) return;
		const answer = decodeOfferOrAnswer(opaque);
		if (!answer) return;
		if (!existing && this.#legs.size >= MAX_LEGS) return;
		const leg = existing ?? new Leg(device);
		leg.answered = true;
		this.#legs.set(device, leg);
		try {
			await this.#startLeg(leg, answer);
		} catch (e) {
			console.warn(`call ${this.id}: answer from device ${device} unusable`, e);
			this.#dropLeg(leg);
		}
	}

	#onCandidate(device: number, sdp: string): void {
		let leg = this.#legs.get(device);
		if (!leg && this.direction === "outgoing" && !this.#active && this.#legs.size < MAX_LEGS) {
			// Before its answer (signaling can reorder): keep it for when the answer comes.
			leg = new Leg(device);
			this.#legs.set(device, leg);
		}
		if (!leg) return;
		if (!leg.ice) {
			if (leg.pending.length < 50) leg.pending.push(sdp);
			return;
		}
		const c = parseCandidate(sdp);
		if (c) leg.ice.addRemoteCandidate(c);
	}

	async #onHangup(device: number, type: number, hangupDevice?: number): Promise<void> {
		if (this.direction === "incoming") {
			if (device !== this.#callerDevice) return;
			// ringrtc call_fsm handle_received_hangup: the caller passing on what another device of ours did.
			if (hangupDevice === this.#host.ourDeviceId) return;
			const reason: CallEndReason =
				type === HANGUP_TYPE.ACCEPTED ? "accepted-elsewhere" : type === HANGUP_TYPE.DECLINED ? "declined-elsewhere" : type === HANGUP_TYPE.BUSY ? "busy-elsewhere" : "remote-hangup";
			this.#end(reason);
			return;
		}
		if (this.#active) {
			if (device === this.#active.device) this.#end("remote-hangup");
			return;
		}
		// Outgoing, not yet accepted: a callee device declining ends the call; tell the others.
		if (type === HANGUP_TYPE.NEED_PERMISSION) {
			await this.#propagate({ id: this.id, type: HANGUP_TYPE.NEED_PERMISSION, deviceId: device }, device);
			this.#end("need-permission");
		} else if (type === HANGUP_TYPE.NORMAL) {
			await this.#propagate({ id: this.id, type: HANGUP_TYPE.DECLINED, deviceId: device }, device);
			this.#end("declined");
		}
	}

	async #onBusy(device: number): Promise<void> {
		if (this.direction !== "outgoing" || this.#active) return;
		await this.#propagate({ id: this.id, type: HANGUP_TYPE.BUSY, deviceId: device }, device);
		this.#end("busy");
	}

	// --- media in ---

	#onData(from: Address, data: Uint8Array): void {
		if (this.state === "ended") return;
		if (isStun(data)) {
			const m = decodeStun(data);
			if (!m) return;
			let leg: Leg | undefined;
			if (m.cls === CLASS.REQUEST) {
				const [ours, theirs] = (attrString(m, ATTR.USERNAME) ?? "").split(":");
				if (ours !== this.#ice.ufrag) return;
				leg = [...this.#legs.values()].find((l) => l.ice && l.ice.remote.ufrag === theirs);
			} else leg = [...this.#legs.values()].find((l) => l.ice?.ownsResponse(m));
			if (leg) void leg.ice.handleStun(from, m);
			return;
		}
		if (!isRtpOrRtcp(data) || isRtcp(data)) return;
		const leg = this.#active && this.#active.ice.knows(from) ? this.#active : [...this.#legs.values()].find((l) => l.ice?.knows(from));
		if (!leg) return;
		void this.#onRtp(leg, data);
	}

	async #onRtp(leg: Leg, data: Uint8Array): Promise<void> {
		const plain = await leg.rx.unprotect(data);
		if (!plain || this.state === "ended") return;
		const p = parseRtp(plain);
		if (!p) return;
		if (p.pt === RTP_DATA_PT && p.ssrc === RTP_DATA_SSRC) {
			const msg = decodeRtpData(p.payload);
			if (msg) await this.#onRtpData(leg, msg);
			return;
		}
		if (p.pt !== OPUS_PT || leg !== this.#active || this.state !== "connected") return;
		const packet = { opus: p.payload, timestamp: p.timestamp, sequence: p.seq };
		try {
			this.onAudio?.(packet, this);
			if (this.#codec && this.onPcm && p.payload.length > 2) this.onPcm(this.#codec.decode(p.payload), this);
		} catch (e) {
			console.error("call audio handler failed", e);
		}
	}

	async #onRtpData(leg: Leg, m: RtpDataMessage): Promise<void> {
		if (m.accepted && m.accepted.id === this.id && this.direction === "outgoing" && !this.#active) {
			this.#active = leg;
			this.#setState("connected");
			// ringrtc handle_remotely_accepted_connection: the other devices stop ringing.
			const hangup = { id: this.id, type: HANGUP_TYPE.ACCEPTED, deviceId: leg.device };
			for (const other of [...this.#legs.values()]) {
				if (other === leg) continue;
				this.#sendRtpData(other, { hangup });
				this.#dropLeg(other);
			}
			void this.#host.send(this.peer, { hangup }, false).catch((e) => console.warn("call: hangup to other devices failed", e));
			this.#startDataTimer();
			this.#pump();
		}
		if (m.hangup && m.hangup.id === this.id && (leg === this.#active || this.direction === "incoming")) {
			if (this.direction === "incoming") await this.#onHangup(leg.device, m.hangup.type, m.hangup.deviceId);
			else this.#end("remote-hangup");
		}
	}

	// --- setup ---

	async #setup(): Promise<void> {
		if (this.#opts.codec && !this.#codec) this.#codec = await this.#opts.codec();
		const servers = turnServers(await this.#host.iceServers());
		this.#turn = await TurnClient.openAny(servers, {
			onData: (from, data) => this.#onData(from, data),
			onClose: (e) => {
				if (this.state !== "ended") {
					console.warn(`call ${this.id}: TURN connection lost`, e);
					void this.#hangupAndEnd("failed");
				}
			},
		});
		if (this.state === "ended") this.#turn.close();
	}

	#localParams(): ConnectionParametersV4 {
		// RingRTC refuses a description without video codecs: offer VP8 (we never send video).
		return { publicKey: this.#publicKey, iceUfrag: this.#ice.ufrag, icePwd: this.#ice.pwd, maxBitrateBps: MAX_BITRATE_BPS, encodeVideoCodecs: [VIDEO_CODEC.VP8], decodeVideoCodecs: [VIDEO_CODEC.VP8] };
	}

	/** Keys and ICE for a leg, from the remote's parameters (their answer, or the offer). */
	async #startLeg(leg: Leg, remote: ConnectionParametersV4): Promise<void> {
		const theirIdentity = await this.#host.peerIdentityKey(this.peer);
		if (!theirIdentity) throw new Error(`call: no identity key recorded for ${this.peer}`);
		const caller = this.direction === "outgoing";
		const keys = await negotiateSrtpKeys(this.#privateKey, remote.publicKey, caller ? this.#host.ourIdentityKey : theirIdentity, caller ? theirIdentity : this.#host.ourIdentityKey);
		leg.tx = await SrtpSession.create(caller ? keys.offer : keys.answer);
		leg.rx = await SrtpSession.create(caller ? keys.answer : keys.offer);
		const turn = this.#turn!;
		leg.ice = new IceSession({
			local: this.#ice,
			remote: { ufrag: remote.iceUfrag, pwd: remote.icePwd },
			controlling: caller,
			tieBreaker: this.#tieBreaker,
			transport: { relay: turn.relayed, send: (to, data) => turn.send(to, data), permit: (ip) => turn.permit(ip) },
			onSelected: () => this.#onLegConnected(leg),
			onFailed: (reason) => this.#onLegFailed(leg, reason),
		});
		for (const sdp of leg.pending.splice(0)) {
			const c = parseCandidate(sdp);
			if (c) leg.ice.addRemoteCandidate(c);
		}
	}

	#onLegConnected(leg: Leg): void {
		if (this.state === "ended") return;
		if (this.direction === "outgoing") {
			if (this.state === "calling") this.#setState("ringing");
			return;
		}
		if (this.#active) return;
		this.#active = leg;
		this.#dataMessage = { accepted: { id: this.id } };
		this.#sendRtpData(leg, this.#dataMessage);
		this.#startDataTimer();
		this.#setState("connected");
		this.#pump();
	}

	#onLegFailed(leg: Leg, reason: string): void {
		console.warn(`call ${this.id}: device ${leg.device}: ${reason}`);
		if (leg === this.#active || this.direction === "incoming") void this.#hangupAndEnd("failed");
		else this.#dropLeg(leg);
	}

	#dropLeg(leg: Leg): void {
		leg.ice?.close();
		this.#legs.delete(leg.device);
	}

	async #sendCandidate(device: number | undefined): Promise<void> {
		const sdp = relayCandidate(this.#turn!.relayed, this.#ice.ufrag);
		await this.#host.send(this.peer, { iceUpdates: [{ id: this.id, opaque: encodeIceCandidate(sdp) }], destinationDeviceId: device }, false);
	}

	// --- media out ---

	#sendRtpData(leg: Leg, m: RtpDataMessage): void {
		const to = leg.ice?.selected;
		if (!to) return;
		leg.dataCounter = (leg.dataCounter + 1) >>> 0;
		const packet = buildRtp({ pt: RTP_DATA_PT, ssrc: RTP_DATA_SSRC, seq: leg.dataCounter & 0xffff, timestamp: leg.dataCounter, marker: false, payload: encodeRtpData(m) });
		this.#sendRtp(leg, to, packet);
	}

	#sendRtp(leg: Leg, to: Address, packet: Uint8Array): void {
		const turn = this.#turn;
		if (!turn) return;
		// One chain per leg: SRTP's rollover counter needs packets protected in sequence order.
		leg.sends = leg.sends.then(async () => turn.send(to, await leg.tx.protect(packet))).catch(() => {});
	}

	#startDataTimer(): void {
		if (this.#dataTimer !== undefined) return;
		const status = { id: this.id, videoEnabled: false, audioEnabled: true };
		this.#dataMessage = { ...this.#dataMessage, senderStatus: status };
		this.#dataTimer = setInterval(() => {
			if (this.#active && this.state === "connected") this.#sendRtpData(this.#active, this.#dataMessage);
		}, RTP_DATA_INTERVAL_MS);
	}

	/** Sends queued audio at real-time pace on the connected leg. */
	#pump(): void {
		if (this.#pacer !== undefined || this.state !== "connected" || !this.#active || !this.#queue.length) return;
		const tick = () => {
			this.#pacer = undefined;
			const leg = this.#active;
			const to = leg?.ice.selected;
			if (this.state !== "connected" || !leg || !to) return;
			const now = Date.now();
			let marker = false;
			if (this.#nextAt < now - 200) {
				// Starting, or resuming after a pause: timestamps follow the wall clock across the gap,
				// and the marker bit flags the start of a talkspurt (RFC 3551 §4.1).
				if (this.#tsAt) this.#ts = (this.#ts + Math.max(0, Math.round(((now - this.#tsAt) * OPUS_CLOCK) / 1000))) >>> 0;
				this.#tsAt = now;
				this.#nextAt = now;
				marker = true;
			}
			while (this.#queue.length && this.#nextAt <= now + 20) {
				const opus = this.#queue.shift()!;
				const samples = opusSamples(opus);
				this.#queuedSamples -= samples;
				this.#seq = (this.#seq + 1) & 0xffff;
				this.#sendRtp(leg, to, buildRtp({ pt: OPUS_PT, ssrc: audioSsrc(this.direction === "outgoing"), seq: this.#seq, timestamp: this.#ts, marker, payload: opus }));
				marker = false;
				this.#ts = (this.#ts + samples) >>> 0;
				const ms = (samples * 1000) / OPUS_CLOCK;
				this.#tsAt += ms;
				this.#nextAt += ms;
			}
			if (this.#queue.length) this.#pacer = setTimeout(tick, Math.max(0, this.#nextAt - Date.now() - 20));
		};
		this.#pacer = setTimeout(tick, 0);
	}

	// --- ending ---

	/** Hangup to the caller (incoming) or to every callee device (outgoing), then end. */
	async #hangupAndEnd(reason: CallEndReason): Promise<void> {
		if (this.state === "ended") return;
		const hangup = { id: this.id, type: HANGUP_TYPE.NORMAL };
		if (this.#active) for (let i = 0; i < 3; i++) this.#sendRtpData(this.#active, { hangup });
		const active = this.#active;
		const sends = active?.sends;
		this.#end(reason);
		await sends?.catch(() => {});
		const destinationDeviceId = this.direction === "incoming" ? this.#callerDevice : undefined;
		await this.#host.send(this.peer, { hangup, destinationDeviceId }, false).catch((e) => console.warn("call: sending hangup failed", e));
	}

	/** Caller: passes a callee device's hangup or busy on to the other callee devices. */
	async #propagate(hangup: { id: bigint; type: number; deviceId: number }, except: number): Promise<void> {
		for (const leg of this.#legs.values()) if (leg.device !== except) this.#sendRtpData(leg, { hangup });
		await this.#host.send(this.peer, { hangup }, false).catch((e) => console.warn("call: propagating hangup failed", e));
	}

	#end(reason: CallEndReason): void {
		if (this.state === "ended") return;
		this.endReason = reason;
		for (const t of this.#timers) clearTimeout(t);
		this.#timers.clear();
		if (this.#dataTimer !== undefined) clearInterval(this.#dataTimer);
		if (this.#pacer !== undefined) clearTimeout(this.#pacer);
		const legs = [...this.#legs.values()];
		this.#legs.clear();
		const turn = this.#turn;
		// Let the last packets (hangup over RTP data) out before the relay goes.
		void Promise.all(legs.map((l) => l.sends)).finally(() => {
			for (const l of legs) l.ice?.close();
			turn?.close();
		});
		this.#queue = [];
		this.#queuedSamples = 0;
		try {
			this.#codec?.free?.();
		} catch {}
		this.#setState("ended");
		this.#resolveEnded(reason);
		this.#onFinished(this);
	}

	/** A method, so TypeScript doesn't narrow `state` across awaits. */
	#isEnded(): boolean {
		return this.state === "ended";
	}

	#setState(s: CallState): void {
		if (this.state === s) return;
		this.state = s;
		try {
			this.onState?.(s, this);
		} catch (e) {
			console.error("call state handler failed", e);
		}
	}

	#after(ms: number, fn: () => void): void {
		const t = setTimeout(() => {
			this.#timers.delete(t);
			fn();
		}, ms);
		this.#timers.add(t);
	}
}

/**
 * The account's calls: routes incoming CallMessages, answers busy while a call is up, and places
 * calls. One call at a time, as Signal's apps.
 */
export class CallManager {
	#host: CallHost;
	#calls = new Map<bigint, SignalCall>();
	#onIncoming?: (call: SignalCall) => void;
	#opts: CallOptions;

	constructor(host: CallHost, onIncoming: ((call: SignalCall) => void) | undefined, opts: CallOptions = {}) {
		this.#host = host;
		this.#onIncoming = onIncoming;
		this.#opts = opts;
	}

	get calls(): SignalCall[] {
		return [...this.#calls.values()];
	}

	async start(peer: string, opts: CallOptions = {}): Promise<SignalCall> {
		if (this.#calls.size) throw new Error("a call is already in progress");
		return SignalCall.outgoing(this.#host, peer, { ...this.#opts, ...opts }, {
			onCreated: (c) => this.#calls.set(c.id, c),
			onFinished: (c) => this.#calls.delete(c.id),
		});
	}

	/** A CallMessage from `sender`'s `device`; `sentAt` is the server timestamp (offers expire). */
	async handle(sender: string, device: number, message: CallMessage, sentAt: number | undefined, now = Date.now()): Promise<"incoming" | "busy" | "handled" | "ignored"> {
		if (sender === this.#host.ourAci) return "ignored"; // our other devices' calls aren't ours to take part in
		if (message.destinationDeviceId && message.destinationDeviceId !== this.#host.ourDeviceId) return "ignored";
		if (message.offer) {
			const { id, type, opaque } = message.offer;
			if (this.#calls.has(id)) return "ignored";
			if (sentAt !== undefined && now - sentAt > MAX_OFFER_AGE_MS) return "ignored";
			const offer = decodeOfferOrAnswer(opaque);
			if (!offer || !this.#onIncoming) return "ignored";
			if (this.#calls.size) {
				await this.#host.send(sender, { busy: { id }, destinationDeviceId: device }, false);
				return "busy";
			}
			const call = SignalCall.incoming(this.#host, sender, device, id, type === OFFER_TYPE.VIDEO, offer, this.#opts, (c) => this.#calls.delete(c.id));
			this.#calls.set(id, call);
			try {
				this.#onIncoming(call);
			} catch (e) {
				console.error("incoming call handler failed", e);
			}
			return "incoming";
		}
		const id = message.answer?.id ?? message.iceUpdates?.[0]?.id ?? message.hangup?.id ?? message.busy?.id;
		const call = id === undefined ? undefined : this.#calls.get(id);
		if (!call || call.peer !== sender) return "ignored";
		await call.handleMessage(device, message);
		return "handled";
	}

	/** Ends every call (the account is being reset). */
	async endAll(): Promise<void> {
		await Promise.all(this.calls.map((c) => c.hangup().catch(() => {})));
	}
}

function randomCallId(): bigint {
	return new DataView(randomBytes(8).buffer).getBigUint64(0);
}
function randomU16(): number {
	return new DataView(randomBytes(2).buffer).getUint16(0);
}
function randomU32(): number {
	return new DataView(randomBytes(4).buffer).getUint32(0);
}
