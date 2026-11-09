import assert from "node:assert/strict";
import { test } from "node:test";
import { memoryDb, TEST_STORAGE_KEY } from "./node-host.mjs";
import { Sealer } from "../dist/index.js";
import { linkCryptoSelfTest, receiverSelfTest, storeSelfTest } from "../dist/selftest/index.js";

function passed(result) {
	const failed = Object.entries(result).filter(([, v]) => v === false).map(([k]) => k);
	assert.equal(result.ok, true, `failed checks: ${failed.join(", ")}\n${JSON.stringify(result, null, 2)}`);
}

test("link crypto: X25519 vector, device name, provisioning envelope, tamper rejection", async () => {
	passed(await linkCryptoSelfTest());
});

test("protocol store survives restarts, consumes one-time keys, rejects replays", async () => {
	passed(await storeSelfTest(memoryDb(), await Sealer.fromBase64(TEST_STORAGE_KEY)));
});

test("receive path: sealed sender, group SKDM, identity change, retry requests, send log", async () => {
	passed(await receiverSelfTest(memoryDb(), await Sealer.fromBase64(TEST_STORAGE_KEY)));
});
