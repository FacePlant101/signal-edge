#!/usr/bin/env node
// A Signal linked device in a terminal, on signal-edge's Node adapter.
//
//   export SIGNAL_STORAGE_KEY=$(openssl rand -base64 32)   # keep it: it encrypts the database
//   node signal.mjs link            # prints an sgnl:// URL: show it as a QR code (qrencode -t ansiutf8 '<url>')
//   node signal.mjs status
//   node signal.mjs listen          # prints incoming messages until Ctrl-C
//   node signal.mjs send self "hello from Node"     # or aci:<uuid>, group:<id>
//
// SIGNAL_DB picks the database file (default ./signal.db). Use a spare number while trying it out.
import { createNodeClient } from "signal-edge/node";

const [command, ...args] = process.argv.slice(2);
if (!process.env.SIGNAL_STORAGE_KEY) fail("set SIGNAL_STORAGE_KEY (32 random bytes, base64: openssl rand -base64 32)");

const { client, shutdown } = createNodeClient({
	database: process.env.SIGNAL_DB ?? "signal.db",
	storageKey: process.env.SIGNAL_STORAGE_KEY,
	deviceName: "signal-edge (Node)",
	onMessages: (records) => {
		for (const r of records) if (r.kind === "message" && r.body) console.log(`${new Date(r.sentAt).toISOString()} ${r.conversation} ${r.outgoing ? "→" : "←"} ${r.body}`);
	},
});
process.once("SIGINT", () => void shutdown().then(() => process.exit(0)));

try {
	switch (command) {
		case "link": {
			const state = await client.startLink();
			if (state.state === "linked") break;
			if (state.state !== "waiting_for_scan") fail(JSON.stringify(state));
			console.log(`Scan in Signal → Settings → Linked devices:\n\n${state.url}\n\nWaiting (the code expires after a few minutes)…`);
			while (["waiting_for_scan", "linking"].includes(client.status().state)) await new Promise((r) => setTimeout(r, 1000));
			console.log(client.status());
			break;
		}
		case "status":
			console.log(client.status(), client.receiveStatus());
			break;
		case "listen":
			if (client.status().state !== "linked") fail("not linked; run: node signal.mjs link");
			await client.startReceiving();
			console.log("Listening; Ctrl-C to stop.");
			await new Promise(() => {}); // the SIGINT handler exits
			break;
		case "send": {
			const [to, ...words] = args;
			if (!to || !words.length) fail('usage: node signal.mjs send <self|aci:<uuid>|group:<id>> "text"');
			console.log(await client.sendText(to, words.join(" ")));
			break;
		}
		default:
			fail("commands: link, status, listen, send");
	}
} catch (e) {
	console.error(e instanceof Error ? e.message : e);
	process.exitCode = 1;
} finally {
	await shutdown();
}

function fail(message) {
	console.error(message);
	process.exit(1);
}
