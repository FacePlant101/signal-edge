// Talks to Signal's real servers, without an account: pinned TLS to chat.signal.org, a public CA
// refused, and the provisioning socket. Runs only with SIGNAL_NETWORK_TESTS=1 (CI sets it; sandboxes
// without raw TCP can't run it).
import assert from "node:assert/strict";
import { test } from "node:test";
import { CHAT_HOST, decodeProvisioningAddress, signalFetch, SignalSocket } from "signal-edge/node";

const skip = process.env.SIGNAL_NETWORK_TESTS !== "1" && "set SIGNAL_NETWORK_TESTS=1 to talk to Signal's servers";

test("HTTPS to chat.signal.org over TLS pinned to Signal's roots", { skip }, async () => {
	const res = await signalFetch(CHAT_HOST, "GET", "/v1/config");
	// Unauthenticated: any HTTP answer proves TLS, HTTP and the pinned roots work.
	assert.ok(res.status >= 200 && res.status < 500, `HTTP ${res.status}`);
});

test("a host with a public CA certificate is refused", { skip }, async () => {
	await assert.rejects(signalFetch("github.com", "GET", "/"));
});

test("provisioning socket: Signal sends an address, keepalive answers", { skip }, async () => {
	let gotAddress;
	const address = new Promise((r) => (gotAddress = r));
	const sock = await SignalSocket.connect("/v1/websocket/provisioning/", {
		onRequest: (req) => {
			if (req.verb === "PUT" && req.path === "/v1/address" && req.body) {
				gotAddress(decodeProvisioningAddress(req.body) ?? "");
				return 200;
			}
			return 400;
		},
		onClose: () => {},
	});
	try {
		const uuid = await Promise.race([address, new Promise((_, rej) => setTimeout(() => rej(new Error("no address in 10 s")), 10_000))]);
		assert.ok(uuid.length > 0);
		assert.equal((await sock.request("GET", "/v1/keepalive")).status, 200);
	} finally {
		await sock.close();
	}
});
