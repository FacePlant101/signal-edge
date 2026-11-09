import * as sig from "@getmaapp/signal-wasm";
import { wasmModule } from "../runtime.js";

let ready = false;

/** Initializes libsignal-wasm once per isolate; returns the module for convenience. */
export function signal(): typeof sig {
	if (!ready) {
		sig.initSync({ module: wasmModule("signal") });
		sig.init();
		ready = true;
	}
	return sig;
}
