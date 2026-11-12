// Whole calls between our own call stacks, through an in-process TURN server (RFC 8656 over TCP, with
// long-term auth, permissions and channels): signaling, ICE, SRTP, RTP data, audio, and the endings.
// What this can't show is interop with RingRTC itself; that needs a phone (see README "Calls").
import assert from "node:assert/strict";
import { test } from "node:test";
import "./node-host.mjs";
import { configure, CallManager, encodeCallMessage, decodeCallMessage } from "../dist/index.js";
import { ATTR, CLASS, METHOD, attr, attrString, checkIntegrity, decodeStun, encodeStun, longTermKey, readXorAddress, xorAddress, value } from "../dist/calling/stun.js";

// --- a fake TURN server ---

const REALM = "test.invalid";
const USER = "turnuser";
const PASS = "turnpass";

class FakeTurn {
	allocations = new Map(); // "ip|port" → allocation
	next = 1;
	connections = 0;
	stats = { channelData: 0, sendIndications: 0, dropped: 0 };

	connect() {
		this.connections++;
		const server = this;
		let toClient;
		const readable = new ReadableStream({ start: (c) => (toClient = c) });
		const alloc = { permissions: new Set(), channels: new Map(), peers: new Map(), relayed: undefined, closed: false };
		let buf = new Uint8Array(0);
		const send = (bytes) => {
			if (alloc.closed) return;
			// Split arbitrarily: the client must reassemble frames from a byte stream.
			const cut = Math.floor(bytes.length / 2);
			if (cut > 0 && Math.random() < 0.5) {
				toClient.enqueue(bytes.slice(0, cut));
				toClient.enqueue(bytes.slice(cut));
			} else toClient.enqueue(bytes);
		};
		alloc.deliver = (from, data) => {
			if (!alloc.permissions.has(from.ip)) {
				server.stats.dropped++;
				return;
			}
			const ch = alloc.peers.get(`${from.ip}|${from.port}`);
			if (ch !== undefined) {
				const pad = (4 - (data.length % 4)) % 4;
				const out = new Uint8Array(4 + data.length + pad);
				out.set([ch >> 8, ch & 0xff, data.length >> 8, data.length & 0xff]);
				out.set(data, 4);
				send(out);
			} else {
				const txId = crypto.getRandomValues(new Uint8Array(12));
				void encodeStun({ method: METHOD.DATA, cls: CLASS.INDICATION, txId, attrs: [[ATTR.XOR_PEER_ADDRESS, xorAddress(from, txId)], [ATTR.DATA, data]] }).then(send);
			}
		};
		const relay = (to, data) => {
			const target = server.allocations.get(`${to.ip}|${to.port}`);
			if (alloc.permissions.has(to.ip) && target) target.deliver(alloc.relayed, data);
			else server.stats.dropped++;
		};
		const key = longTermKey(USER, REALM, PASS);
		const reply = async (m, cls, attrs) => send(await encodeStun({ method: m.method, cls, txId: m.txId, attrs }, { integrityKey: key }));
		const error = async (m, code, extra = []) =>
			send(await encodeStun({ method: m.method, cls: CLASS.ERROR, txId: m.txId, attrs: [[ATTR.ERROR_CODE, new Uint8Array([0, 0, Math.floor(code / 100), code % 100])], ...extra] }));
		const onStun = async (m) => {
			if (m.cls === CLASS.INDICATION && m.method === METHOD.SEND) {
				server.stats.sendIndications++;
				relay(readXorAddress(attr(m, ATTR.XOR_PEER_ADDRESS), m.txId), attr(m, ATTR.DATA));
				return;
			}
			if (m.cls !== CLASS.REQUEST) return;
			if (attrString(m, ATTR.USERNAME) !== USER || attrString(m, ATTR.NONCE) !== "nonce-1" || !(await checkIntegrity(m, key))) {
				await error(m, 401, [
					[ATTR.REALM, value.string(REALM)],
					[ATTR.NONCE, value.string("nonce-1")],
				]);
				return;
			}
			if (m.method === METHOD.ALLOCATE) {
				alloc.relayed = { ip: `198.51.100.${server.next}`, port: 40000 + server.next };
				server.next++;
				server.allocations.set(`${alloc.relayed.ip}|${alloc.relayed.port}`, alloc);
				await reply(m, CLASS.SUCCESS, [
					[ATTR.XOR_RELAYED_ADDRESS, xorAddress(alloc.relayed, m.txId)],
					[ATTR.XOR_MAPPED_ADDRESS, xorAddress({ ip: "203.0.113.50", port: 5000 }, m.txId)],
					[ATTR.LIFETIME, value.u32(600)],
				]);
			} else if (m.method === METHOD.CREATE_PERMISSION) {
				const peer = readXorAddress(attr(m, ATTR.XOR_PEER_ADDRESS), m.txId);
				if (peer.ip.startsWith("10.")) return error(m, 403); // private addresses refused
				alloc.permissions.add(peer.ip);
				await reply(m, CLASS.SUCCESS, []);
			} else if (m.method === METHOD.CHANNEL_BIND) {
				const ch = (attr(m, ATTR.CHANNEL_NUMBER)[0] << 8) | attr(m, ATTR.CHANNEL_NUMBER)[1];
				const peer = readXorAddress(attr(m, ATTR.XOR_PEER_ADDRESS), m.txId);
				alloc.channels.set(ch, peer);
				alloc.peers.set(`${peer.ip}|${peer.port}`, ch);
				alloc.permissions.add(peer.ip);
				await reply(m, CLASS.SUCCESS, []);
			} else if (m.method === METHOD.REFRESH) {
				const lifetime = attr(m, ATTR.LIFETIME);
				if (lifetime && lifetime.every((b) => b === 0)) alloc.closed = true;
				await reply(m, CLASS.SUCCESS, [[ATTR.LIFETIME, value.u32(600)]]);
			}
		};
		const writable = new WritableStream({
			write: async (chunk) => {
				const joined = new Uint8Array(buf.length + chunk.length);
				joined.set(buf);
				joined.set(chunk, buf.length);
				buf = joined;
				for (;;) {
					if (buf.length < 4) return;
					if ((buf[0] & 0xc0) === 0) {
						const len = 20 + ((buf[2] << 8) | buf[3]);
						if (buf.length < len) return;
						const m = decodeStun(buf.slice(0, len));
						buf = buf.slice(len);
						if (m) await onStun(m);
					} else {
						const ch = (buf[0] << 8) | buf[1];
						const len = (buf[2] << 8) | buf[3];
						const total = 4 + len + ((4 - (len % 4)) % 4);
						if (buf.length < total) return;
						const data = buf.slice(4, 4 + len);
						buf = buf.slice(total);
						const peer = alloc.channels.get(ch);
						server.stats.channelData++;
						if (peer) relay(peer, data);
					}
				}
			},
		});
		return {
			readable,
			writable,
			opened: Promise.resolve(),
			close: async () => {
				alloc.closed = true;
				if (alloc.relayed) server.allocations.delete(`${alloc.relayed.ip}|${alloc.relayed.port}`);
				try {
					toClient.close();
				} catch {}
			},
		};
	}
}

// --- two (or more) accounts wired together ---

const turn = new FakeTurn();
configure({ connect: () => turn.connect() });

function identity(n) {
	const k = new Uint8Array(33).fill(n);
	k[0] = 5;
	return k;
}

const ACI = { alice: "aaaaaaaa-0000-4000-8000-000000000001", bob: "bbbbbbbb-0000-4000-8000-000000000002" };

/** Account `name` with devices; send() delivers through the wire format to every device of the recipient. */
function network({ iceFirst = false } = {}) {
	const devices = new Map(); // aci → [{ deviceId, manager }]
	const log = [];
	const add = (name, deviceId, onIncoming) => {
		const aci = ACI[name];
		const host = {
			ourAci: aci,
			ourDeviceId: deviceId,
			ourIdentityKey: identity(name === "alice" ? 1 : 2),
			peerIdentityKey: async (peer) => identity(peer === ACI.alice ? 1 : 2),
			iceServers: async () => [{ username: USER, password: PASS, urls: ["turn:turn.test.invalid:3478?transport=tcp"] }],
			send: async (to, m, urgent) => {
				log.push({ from: `${name}.${deviceId}`, to, kind: Object.keys(m).filter((k) => m[k] !== undefined), urgent });
				const bytes = encodeCallMessage(m);
				// Delivered asynchronously, in order, as the chat socket would.
				// iceFirst: candidates overtake answers (signaling can reorder across sends).
				const delay = iceFirst ? (m.answer ? 40 : 1) : 5;
				for (const d of devices.get(to) ?? []) setTimeout(() => void d.manager.handle(aci, deviceId, decodeCallMessage(bytes), Date.now()), delay);
			},
		};
		const manager = new CallManager(host, onIncoming);
		const list = devices.get(aci) ?? [];
		list.push({ deviceId, manager });
		devices.set(aci, list);
		return manager;
	};
	return { add, log };
}

const until = async (what, cond, ms = 10_000) => {
	const end = Date.now() + ms;
	while (!cond()) {
		if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
		await new Promise((r) => setTimeout(r, 10));
	}
};

/** A 20 ms CELT Opus packet (TOC 0x78) whose payload counts. */
const opus = (n) => new Uint8Array([0x78, n & 0xff, (n >> 8) & 0xff, 0xaa]);

test("a call: ring, answer, two-way audio paced at real time, hang up", async () => {
	const net = network();
	let incoming;
	const states = [];
	net.add("bob", 1, (call) => {
		incoming = call;
		call.onState = (s) => states.push(`bob:${s}`);
	});
	const alice = net.add("alice", 1);
	const call = await alice.start(ACI.bob);
	call.onState = (s) => states.push(`alice:${s}`);
	assert.equal(call.state, "calling");
	assert.ok(net.log[0].kind.includes("offer") && net.log[0].urgent, "the offer goes out urgent");

	await until("the incoming call", () => incoming);
	assert.equal(incoming.peer, ACI.alice);
	assert.equal(incoming.id, call.id);
	assert.equal(incoming.state, "ringing");

	const aliceHeard = [];
	const bobHeard = [];
	call.onAudio = (p) => aliceHeard.push(p.opus[1]);
	incoming.onAudio = (p) => bobHeard.push(p.opus[1]);
	// Queued before the call connects: held, then sent.
	for (let i = 0; i < 25; i++) call.sendAudio(opus(i));
	assert.equal(call.queuedMs, 500);

	// Candidates ICE can't use, ranked above the relay: a private address the TURN server refuses, an
	// mDNS name and TCP. The call must still connect through the relay.
	const { encodeIceCandidate } = await import("../dist/calling/signaling.js");
	const junk = ["candidate:9 1 udp 2130706431 10.0.0.5 5000 typ host", "candidate:8 1 udp 2130706430 abcd.local 5001 typ host", "candidate:7 1 tcp 2130706429 192.0.2.99 9 typ host tcptype active"];
	await alice.handle(ACI.bob, 1, { iceUpdates: junk.map((sdp) => ({ id: call.id, opaque: encodeIceCandidate(sdp) })) }, Date.now());
	await incoming.accept();
	await until("both sides connected", () => call.state === "connected" && incoming.state === "connected");
	assert.deepEqual(states.filter((s) => s.startsWith("bob")), ["bob:connecting", "bob:connected"]);
	assert.ok(states.includes("alice:connected"));

	const started = Date.now();
	await until("bob hears alice", () => bobHeard.length === 25);
	assert.deepEqual(bobHeard, [...Array(25).keys()]);
	// 25 × 20 ms = 500 ms of audio: paced, not dumped at once (with slack for the 20 ms lead).
	assert.ok(Date.now() - started >= 400, `paced (${Date.now() - started} ms)`);

	for (let i = 100; i < 110; i++) incoming.sendAudio(opus(i));
	await until("alice hears bob", () => aliceHeard.length === 10);
	assert.deepEqual(aliceHeard, [...Array(10).keys()].map((i) => i + 100));
	assert.ok(turn.stats.channelData > 0, "media rides TURN channels");

	await call.hangup();
	assert.equal(await call.ended, "hangup");
	assert.equal(await incoming.ended, "remote-hangup");
	assert.equal((await Promise.resolve(alice.calls)).length, 0);
});

test("two callee devices: the one that answers wins, the other is told (candidates before the answer)", async () => {
	const net = network({ iceFirst: true });
	const rung = [];
	net.add("bob", 1, (c) => rung.push(c));
	net.add("bob", 2, (c) => rung.push(c));
	const alice = net.add("alice", 1);
	const call = await alice.start(ACI.bob);
	await until("both devices ring", () => rung.length === 2);
	const [one, two] = rung;
	await two.accept();
	await until("connected to device 2", () => call.state === "connected");
	assert.equal(call.remoteDevice, 2);
	assert.equal(await one.ended, "accepted-elsewhere");
	const hangupToOthers = net.log.find((l) => l.from === "alice.1" && l.kind.includes("hangup"));
	assert.ok(hangupToOthers, "alice told bob's other devices");
	await two.hangup();
	assert.equal(await call.ended, "remote-hangup");
	assert.equal(await two.ended, "hangup");
});

test("declined, busy, and cancelled calls end the right way", async () => {
	{
		const net = network();
		net.add("bob", 1, (c) => void c.decline());
		const alice = net.add("alice", 1);
		const call = await alice.start(ACI.bob);
		assert.equal(await call.ended, "declined");
	}
	{
		const net = network();
		const bobCalls = [];
		const bob = net.add("bob", 1, (c) => bobCalls.push(c));
		const alice = net.add("alice", 1);
		// Bob is already on a call (with someone else): his manager answers busy.
		const other = await bob.start("cccccccc-0000-4000-8000-000000000003").catch(() => undefined);
		const call = await alice.start(ACI.bob);
		assert.equal(await call.ended, "busy");
		assert.equal(bobCalls.length, 0);
		await other?.hangup();
	}
	{
		const net = network();
		let incoming;
		net.add("bob", 1, (c) => (incoming = c));
		const alice = net.add("alice", 1);
		const call = await alice.start(ACI.bob);
		await until("ringing", () => incoming);
		await call.hangup();
		assert.equal(await incoming.ended, "remote-hangup");
	}
});

test("stale offers, messages for other devices, and strangers' hangups are ignored", async () => {
	const host = { ourAci: ACI.bob, ourDeviceId: 1, ourIdentityKey: identity(2), peerIdentityKey: async () => identity(1), iceServers: async () => [], send: async () => {} };
	let rung = 0;
	const m = new CallManager(host, () => rung++);
	const { encodeOfferOrAnswer } = await import("../dist/calling/signaling.js");
	const offer = { id: 7n, type: 0, opaque: encodeOfferOrAnswer({ publicKey: new Uint8Array(32).fill(1), iceUfrag: "uuuu", icePwd: "p".repeat(24), encodeVideoCodecs: [8], decodeVideoCodecs: [8] }) };
	assert.equal(await m.handle(ACI.alice, 1, { offer }, Date.now() - 61_000), "ignored", "older than a minute");
	assert.equal(await m.handle(ACI.alice, 1, { offer, destinationDeviceId: 2 }, Date.now()), "ignored", "for another device");
	assert.equal(await m.handle(ACI.bob, 2, { offer }, Date.now()), "ignored", "from our own account");
	assert.equal(await m.handle(ACI.alice, 1, { offer }, Date.now()), "incoming");
	assert.equal(rung, 1);
	assert.equal(await m.handle("cccccccc-0000-4000-8000-000000000003", 1, { hangup: { id: 7n, type: 0 } }, Date.now()), "ignored", "a hangup from someone else");
	assert.equal(m.calls[0].state, "ringing");
	await m.calls[0].decline();
});

test("PCM in and out through a pluggable codec, 20 ms frames", async () => {
	// A stand-in "codec": each 960-sample frame becomes a 20 ms CELT packet carrying its first sample.
	const codec = () => ({
		encode: (pcm) => {
			assert.equal(pcm.length, 960);
			return new Uint8Array([0x78, pcm[0] & 0xff, 0]);
		},
		decode: (packet) => new Int16Array(960).fill(packet[1]),
	});
	const net = network();
	let incoming;
	net.add("bob", 1, (c) => (incoming = c));
	const alice = net.add("alice", 1);
	const call = await alice.start(ACI.bob, { codec });
	await until("ringing", () => incoming);
	const heard = [];
	incoming.onAudio = (p) => heard.push(p.opus[1]);
	await incoming.accept();
	await until("connected", () => call.state === "connected" && incoming.state === "connected");
	// 2.5 frames at once, then the rest: framing carries the remainder over.
	const pcm = new Int16Array(960 * 3);
	for (let f = 0; f < 3; f++) pcm.fill(f + 1, f * 960, (f + 1) * 960);
	call.sendPcm(pcm.subarray(0, 2400));
	call.sendPcm(pcm.subarray(2400));
	await until("three frames heard", () => heard.length === 3);
	assert.deepEqual(heard, [1, 2, 3]);
	assert.throws(() => incoming.sendPcm(new Int16Array(960)), /no codec/);
	await call.hangup();
	await incoming.ended;
});
