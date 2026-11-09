// After tsc: copies the wasm-bindgen output (JS glue and .wasm), which tsc doesn't copy, into dist/, and
// moves the Node entry point from its own pass (dist-node/, see tsconfig.node.json) next to the rest.
import { cpSync, renameSync, rmSync } from "node:fs";
const at = (p) => new URL(`../${p}`, import.meta.url);
cpSync(at("src/vendor"), at("dist/vendor"), { recursive: true });
for (const f of ["node.js", "node.js.map", "node.d.ts"]) renameSync(at(`dist-node/${f}`), at(`dist/${f}`));
rmSync(at("dist-node"), { recursive: true });
