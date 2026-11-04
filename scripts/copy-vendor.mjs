// tsc doesn't copy the wasm-bindgen output (JS glue and .wasm); dist imports it next to the compiled code.
import { cpSync } from "node:fs";
cpSync(new URL("../src/vendor", import.meta.url), new URL("../dist/vendor", import.meta.url), { recursive: true });
