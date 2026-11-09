// Wrangler bundles .wasm imports as compiled WebAssembly.Module objects.
declare module "*.wasm" {
	const module: WebAssembly.Module;
	export default module;
}
