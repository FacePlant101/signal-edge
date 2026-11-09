/**
 * Self-tests that need no network or Signal account. Run them against a scratch database only:
 * they create the client's tables and write test rows.
 */
export { storeSelfTest } from "./store-selftest.js";
export { receiverSelfTest } from "./receiver-selftest.js";
export { linkCryptoSelfTest } from "./crypto-selftest.js";
