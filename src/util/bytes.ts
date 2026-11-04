export const enc = new TextEncoder();
export const dec = new TextDecoder();

export function concat(...parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

export function indexOf(haystack: Uint8Array, needle: Uint8Array, from = 0): number {
	outer: for (let i = from; i <= haystack.length - needle.length; i++) {
		for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
		return i;
	}
	return -1;
}

export function toBase64(bytes: Uint8Array): string {
	let s = "";
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s);
}

export function fromBase64(b64: string): Uint8Array {
	const s = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
	const out = new Uint8Array(s.length);
	for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
	return out;
}

export function randomBytes(n: number): Uint8Array {
	return crypto.getRandomValues(new Uint8Array(n));
}

/** Buffers stream chunks so callers can consume exact byte counts or delimited segments. */
export class ByteQueue {
	#buf: Uint8Array = new Uint8Array(0);
	#reader: ReadableStreamDefaultReader<Uint8Array>;

	constructor(stream: ReadableStream<Uint8Array>, initial?: Uint8Array) {
		this.#reader = stream.getReader();
		if (initial) this.#buf = initial;
	}

	/** Reads one more chunk into the buffer; false at end of stream. */
	async fill(): Promise<boolean> {
		const { value, done } = await this.#reader.read();
		if (done) return false;
		this.#buf = this.#buf.length ? concat(this.#buf, value) : value;
		return true;
	}

	async take(n: number): Promise<Uint8Array> {
		while (this.#buf.length < n) if (!(await this.fill())) throw new Error("stream ended early");
		const out = this.#buf.slice(0, n);
		this.#buf = this.#buf.subarray(n);
		return out;
	}

	/** Bytes up to and including `delim`. */
	async takeThrough(delim: Uint8Array, limit = 64 * 1024): Promise<Uint8Array> {
		for (;;) {
			const i = indexOf(this.#buf, delim);
			if (i >= 0) return this.take(i + delim.length);
			if (this.#buf.length > limit) throw new Error("delimiter not found within limit");
			if (!(await this.fill())) throw new Error("stream ended early");
		}
	}

	async rest(): Promise<Uint8Array> {
		while (await this.fill());
		const out = this.#buf;
		this.#buf = new Uint8Array(0);
		return out;
	}

	cancel(): void {
		void this.#reader.cancel().catch(() => {});
	}
}
