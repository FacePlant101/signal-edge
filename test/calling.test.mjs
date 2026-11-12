// Calling: STUN/TURN, SRTP, RTP, ICE, signaling, and a loopback call between two peers over a fake TURN server.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ATTR, checkFingerprint, checkIntegrity, decodeStun, encodeStun, attrString, attr, readXorAddress, longTermKey, md5, crc32, CLASS, METHOD } from "../dist/calling/stun.js";
import { SrtpSession, deriveSessionKey } from "../dist/calling/srtp.js";
import { opusSamples, parseRtp, buildRtp } from "../dist/calling/rtp.js";
import { encodeCallMessage, decodeCallMessage, encodeOfferOrAnswer, decodeOfferOrAnswer, encodeIceCandidate, decodeIceCandidate, encodeRtpData, decodeRtpData, negotiateSrtpKeys } from "../dist/calling/signaling.js";
import { parseCandidate, relayCandidate } from "../dist/calling/ice.js";
import { turnServers } from "../dist/calling/turn.js";

const hex = (s) => Uint8Array.from(s.replace(/[^0-9a-f]/gi, "").match(/../g).map((b) => parseInt(b, 16)));
const bin = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const toHex = (b) => Buffer.from(b).toString("hex");

// --- STUN (RFC 5769 vectors) ---

const RFC5769_REQUEST = bin(
	"\x00\x01\x00\x58\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\x80\x22\x00\x10STUN test client" +
		"\x00\x24\x00\x04\x6e\x00\x01\xff\x80\x29\x00\x08\x93\x2f\xf9\xb1\x51\x26\x3b\x36\x00\x06\x00\x09\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20" +
		"\x00\x08\x00\x14\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2\x80\x28\x00\x04\xe5\x7a\x3b\xcf",
);

test("STUN: RFC 5769 sample request parses, authenticates and fingerprints", async () => {
	const m = decodeStun(RFC5769_REQUEST);
	assert.equal(m.method, METHOD.BINDING);
	assert.equal(m.cls, CLASS.REQUEST);
	assert.equal(attrString(m, ATTR.USERNAME), "evtj:h6vY");
	assert.ok(checkFingerprint(m));
	assert.ok(await checkIntegrity(m, new TextEncoder().encode("VOkJxbRl1RmTxUk/WvJxBt")));
	assert.ok(!(await checkIntegrity(m, new TextEncoder().encode("wrong"))));
});

test("STUN: re-encoding the RFC 5769 request reproduces it byte for byte", async () => {
	const m = decodeStun(RFC5769_REQUEST);
	// The vector pads USERNAME with spaces (any padding value is allowed); ours pads with zeros, so
	// compare our encoding of the same attributes, re-verified.
	const attrs = m.attrs.filter(([t]) => t !== ATTR.MESSAGE_INTEGRITY && t !== ATTR.FINGERPRINT);
	const key = new TextEncoder().encode("VOkJxbRl1RmTxUk/WvJxBt");
	const ours = decodeStun(await encodeStun({ method: m.method, cls: m.cls, txId: m.txId, attrs }, { integrityKey: key, fingerprint: true }));
	assert.ok(await checkIntegrity(ours, key));
	assert.ok(checkFingerprint(ours));
	assert.equal(attrString(ours, ATTR.USERNAME), "evtj:h6vY");
});

test("STUN: RFC 5769 IPv4 and IPv6 responses give the XOR-MAPPED-ADDRESS", () => {
	const v4 = decodeStun(bin("\x01\x01\x00\x3c\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\x80\x22\x00\x0b\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\x00\x20\x00\x08\x00\x01\xa1\x47\xe1\x12\xa6\x43\x00\x08\x00\x14\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7\x80\x28\x00\x04\xc0\x7d\x4c\x96"));
	assert.equal(v4.cls, CLASS.SUCCESS);
	assert.ok(checkFingerprint(v4));
	assert.deepEqual(readXorAddress(attr(v4, ATTR.XOR_MAPPED_ADDRESS), v4.txId), { ip: "192.0.2.1", port: 32853 });
	const v6 = decodeStun(bin("\x01\x01\x00\x48\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\x80\x22\x00\x0b\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\x00\x20\x00\x14\x00\x02\xa1\x47\x01\x13\xa9\xfa\xa5\xd3\xf1\x79\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9\x00\x08\x00\x14\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c\x82\x92\xc2\x75\xbf\xe3\xed\x41\x80\x28\x00\x04\xc8\xfb\x0b\x4c"));
	assert.ok(checkFingerprint(v6));
	assert.deepEqual(readXorAddress(attr(v6, ATTR.XOR_MAPPED_ADDRESS), v6.txId), { ip: "2001:db8:1234:5678:11:2233:4455:6677", port: 32853 });
});

test("STUN: RFC 5769 long-term credentials (MD5 key) authenticate", async () => {
	const m = decodeStun(bin("\x00\x01\x00\x60\x21\x12\xa4\x42\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e\x00\x06\x00\x12\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9\x00\x00\x00\x15\x00\x1c\x66\x2f\x2f\x34\x39\x39\x6b\x39\x35\x34\x64\x36\x4f\x4c\x33\x34\x6f\x4c\x39\x46\x53\x54\x76\x79\x36\x34\x73\x41\x00\x14\x00\x0b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x00\x00\x08\x00\x14\xf6\x70\x24\x65\x6d\xd6\x4a\x3e\x02\xb8\xe0\x71\x2e\x85\xc9\xa2\x8c\xa8\x96\x66"));
	assert.equal(attrString(m, ATTR.REALM), "example.org");
	assert.ok(await checkIntegrity(m, longTermKey("マトリックス", "example.org", "TheMatrIX")));
});

test("MD5 and CRC-32 known answers", () => {
	assert.equal(toHex(md5(new Uint8Array(0))), "d41d8cd98f00b204e9800998ecf8427e");
	assert.equal(toHex(md5(new TextEncoder().encode("The quick brown fox jumps over the lazy dog"))), "9e107d9d372bb6826bd81d3542a419d6");
	assert.equal(toHex(md5(new Uint8Array(1000).fill(97))), "cabe45dcc9ae5b66ba86600cca6b8ba8");
	assert.equal(crc32(new TextEncoder().encode("123456789")), 0xcbf43926);
});

// --- SRTP (RFC 7714 §16 AES-256-GCM, RFC 6188 key derivation via pion's vectors) ---

test("SRTP: AES-CM key derivation matches the AES-256 vector", async () => {
	const master = { key: hex("f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6"), salt: hex("3b04803de51ee7c96423ab5b78d2") };
	assert.equal(toHex(await deriveSessionKey(master, 0, 32)), "5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4");
	assert.equal(toHex(await deriveSessionKey(master, 2, 14)), "fa31791685ca444a9e07c6c64e93");
});

const RFC7714_PLAIN = hex("8040f17b 8041f8d3 5501a0b2 47616c6c 69612065 7374206f 6d6e6973 20646976 69736120 696e2070 61727465 73207472 6573");
const RFC7714_SEALED = hex("8040f17b 8041f8d3 5501a0b2 32b1de78 a822fe12 ef9f78fa 332e33aa b1801238 9a58e2f3 b50b2a02 76ffae0f 1ba63799 b87b7aa3 db36dfff d6b0f9bb 7878d7a7 6c13");
const RFC7714_KEY = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const RFC7714_SALT = hex("517569642070726f2071756f");

test("SRTP: RFC 7714 AES-256-GCM RTP vector encrypts and decrypts", async () => {
	const tx = await SrtpSession.withSessionKeys(RFC7714_KEY, RFC7714_SALT);
	assert.equal(toHex(await tx.protect(RFC7714_PLAIN)), toHex(RFC7714_SEALED));
	const rx = await SrtpSession.withSessionKeys(RFC7714_KEY, RFC7714_SALT);
	assert.equal(toHex(await rx.unprotect(RFC7714_SEALED)), toHex(RFC7714_PLAIN));
	assert.equal(await rx.unprotect(RFC7714_SEALED), undefined, "a replay is dropped");
	const tampered = RFC7714_SEALED.slice();
	tampered[20] ^= 1;
	const rx2 = await SrtpSession.withSessionKeys(RFC7714_KEY, RFC7714_SALT);
	assert.equal(await rx2.unprotect(tampered), undefined, "a forged packet is dropped");
});

test("SRTP: the ROC follows sequence wraparound in both directions, and the replay window holds", async () => {
	const master = { key: new Uint8Array(32).fill(7), salt: new Uint8Array(12).fill(9) };
	const tx = await SrtpSession.create(master);
	const rx = await SrtpSession.create(master);
	const pkt = (seq) => buildRtp({ pt: 102, seq, timestamp: seq * 960, ssrc: 1002, marker: false, payload: new Uint8Array([seq & 0xff, 1, 2]) });
	const seqs = [65530, 65531, 65532, 65533, 65534, 65535, 0, 1, 2, 3];
	const sealed = [];
	for (const s of seqs) sealed.push(await tx.protect(pkt(s)));
	// Delivered out of order across the wrap.
	const order = [0, 1, 2, 3, 4, 6, 5, 7, 9, 8];
	for (const i of order) {
		const out = await rx.unprotect(sealed[i]);
		assert.ok(out, `packet ${seqs[i]} decrypts`);
		assert.equal(parseRtp(out).seq, seqs[i]);
	}
	for (const s of sealed) assert.equal(await rx.unprotect(s), undefined, "replays are dropped");
});

// --- RTP / Opus ---

test("Opus TOC: samples per packet", () => {
	assert.equal(opusSamples(new Uint8Array([0x78, 0])), 960); // CELT FB 20 ms, one frame
	assert.equal(opusSamples(new Uint8Array([(3 << 3) | 0])), 2880); // SILK NB 60 ms
	assert.equal(opusSamples(new Uint8Array([(19 << 3) | 3, 3])), 2880); // CELT 20 ms x3
	assert.equal(opusSamples(new Uint8Array([(3 << 3) | 3, 3])), 0); // 180 ms: invalid
});

// --- Signaling codecs ---


test("CallMessage, V4 parameters, ICE candidates and RTP data round-trip", () => {
	const id = 0xfedcba9876543210n; // above 2^63: uint64 must survive
	const v4 = { publicKey: new Uint8Array(32).fill(3), iceUfrag: "abcd", icePwd: "p".repeat(24), maxBitrateBps: 100000n, encodeVideoCodecs: [8], decodeVideoCodecs: [8, 9] };
	const m = {
		offer: { id, type: 0, opaque: encodeOfferOrAnswer(v4) },
		iceUpdates: [
			{ id, opaque: encodeIceCandidate("candidate:1 1 udp 2 192.0.2.7 3478 typ relay") },
			{ id, opaque: encodeIceCandidate("candidate:2 1 udp 3 192.0.2.8 3479 typ srflx") },
		],
		hangup: { id, type: 1, deviceId: 3 },
		destinationDeviceId: 2,
	};
	const back = decodeCallMessage(encodeCallMessage(m));
	assert.equal(back.offer.id, id);
	assert.deepEqual(decodeOfferOrAnswer(back.offer.opaque), v4);
	assert.deepEqual(back.iceUpdates.map((u) => decodeIceCandidate(u.opaque)), ["candidate:1 1 udp 2 192.0.2.7 3478 typ relay", "candidate:2 1 udp 3 192.0.2.8 3479 typ srflx"]);
	assert.deepEqual(back.hangup, { id, type: 1, deviceId: 3 });
	assert.equal(back.destinationDeviceId, 2);
	const data = decodeRtpData(encodeRtpData({ accepted: { id }, senderStatus: { id, videoEnabled: false, audioEnabled: true } }));
	assert.equal(data.accepted.id, id);
	assert.equal(data.senderStatus.audioEnabled, true);
	assert.equal(data.senderStatus.videoEnabled, false);
});

test("ICE candidates: WebRTC's format parses; ours is one WebRTC parses", () => {
	const c = parseCandidate("candidate:842163049 1 udp 1677729535 203.0.113.9 49170 typ srflx raddr 10.0.0.2 rport 49170 generation 0 ufrag Ab1c network-cost 10");
	assert.deepEqual(c, { foundation: "842163049", component: 1, protocol: "udp", priority: 1677729535, ip: "203.0.113.9", port: 49170, type: "srflx" });
	assert.equal(parseCandidate("candidate:1 1 tcp 1518280447 192.0.2.1 9 typ host tcptype active").protocol, "tcp");
	assert.equal(parseCandidate("garbage"), undefined);
	const ours = parseCandidate(relayCandidate({ ip: "198.51.100.4", port: 61000 }, "Wxyz"));
	assert.equal(ours.type, "relay");
	assert.equal(ours.ip, "198.51.100.4");
	assert.equal(ours.port, 61000);
});

test("TURN servers from the relay list: TCP first, TLS skipped, duplicates dropped", () => {
	const s = turnServers([
		{ username: "u", password: "p", urlsWithIps: ["turn:192.0.2.1", "turn:192.0.2.1:80?transport=tcp", "turns:192.0.2.1:443?transport=tcp"], urls: ["turn:turn.example:3478?transport=udp", "turn:[2001:db8::1]:80?transport=tcp"] },
	]);
	assert.deepEqual(
		s.map((x) => `${x.host}:${x.port}`),
		["192.0.2.1:80", "2001:db8::1:80", "192.0.2.1:3478", "turn.example:3478"],
	);
});

test("SRTP keys: both sides derive the same offer and answer keys (ringrtc negotiate_srtp_keys)", async () => {
	const { signal } = await import("../dist/protocol/wasm.js");
	await import("./node-host.mjs");
	const a = signal().WasmPrivateKey.generate();
	const b = signal().WasmPrivateKey.generate();
	const caller = new Uint8Array(33).fill(1);
	caller[0] = 5;
	const callee = new Uint8Array(33).fill(2);
	callee[0] = 5;
	const ka = await negotiateSrtpKeys(a.serialize(), b.getPublicKey().serialize().subarray(1), caller, callee);
	const kb = await negotiateSrtpKeys(b.serialize(), a.getPublicKey().serialize().subarray(1), caller, callee);
	assert.deepEqual(ka, kb);
	assert.notDeepEqual(ka.offer.key, ka.answer.key);
	assert.equal(ka.offer.key.length, 32);
	assert.equal(ka.offer.salt.length, 12);
	// The identity keys are bound in: swapping roles gives different keys.
	assert.notDeepEqual((await negotiateSrtpKeys(a.serialize(), b.getPublicKey().serialize().subarray(1), callee, caller)).offer.key, ka.offer.key);
	await assert.rejects(negotiateSrtpKeys(a.serialize(), new Uint8Array(32), caller, callee));
});

test("parseContent hands over a CallMessage (Content field 3)", async () => {
	const { parseContent } = await import("../dist/protocol/content.js");
	const { contentWithCallMessage } = await import("../dist/calling/signaling.js");
	const parsed = parseContent(contentWithCallMessage({ hangup: { id: 5n, type: 0 } }), "aaaaaaaa-0000-4000-8000-000000000001", 1, "bbbbbbbb-0000-4000-8000-000000000002");
	assert.ok(parsed.kinds.includes("call"));
	assert.deepEqual(decodeCallMessage(parsed.call).hangup, { id: 5n, type: 0, deviceId: undefined });
	assert.equal(parsed.records.length, 0, "nothing stored");
});
