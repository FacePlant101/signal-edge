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
	/** Unread bytes, as received: joined only when a caller takes them, so buffering stays linear. */
	#chunks: Uint8Array[] = [];
	#length = 0;
	#reader: ReadableStreamDefaultReader<Uint8Array>;

	constructor(stream: ReadableStream<Uint8Array>, initial?: Uint8Array) {
		this.#reader = stream.getReader();
		if (initial?.length) this.#push(initial);
	}

	/** Bytes buffered and not yet taken. */
	get length(): number {
		return this.#length;
	}

	/** Reads one more chunk into the buffer; false at end of stream. */
	async fill(): Promise<boolean> {
		const { value, done } = await this.#reader.read();
		if (done) return false;
		if (value.length) this.#push(value);
		return true;
	}

	async take(n: number): Promise<Uint8Array> {
		while (this.#length < n) if (!(await this.fill())) throw new Error("stream ended early");
		return this.#consume(n);
	}

	/** Bytes up to and including `delim`. */
	async takeThrough(delim: Uint8Array, limit = 64 * 1024): Promise<Uint8Array> {
		for (;;) {
			const i = indexOf(this.#flatten(), delim);
			if (i >= 0) return this.take(i + delim.length);
			if (this.#length > limit) throw new Error("delimiter not found within limit");
			if (!(await this.fill())) throw new Error("stream ended early");
		}
	}

	/** Everything until the stream ends; throws once more than `limit` bytes have arrived. */
	async rest(limit = Infinity): Promise<Uint8Array> {
		while (await this.fill()) if (this.#length > limit) throw new Error(`response larger than ${limit} bytes`);
		return this.#consume(this.#length);
	}

	cancel(): void {
		void this.#reader.cancel().catch(() => {});
	}

	#push(chunk: Uint8Array): void {
		this.#chunks.push(chunk);
		this.#length += chunk.length;
	}

	/** Joins the buffered chunks into one (for searching). */
	#flatten(): Uint8Array {
		if (this.#chunks.length > 1) this.#chunks = [concat(...this.#chunks)];
		return this.#chunks[0] ?? new Uint8Array(0);
	}

	#consume(n: number): Uint8Array {
		const out = new Uint8Array(n);
		let off = 0;
		while (off < n) {
			const head = this.#chunks[0]!;
			const k = Math.min(head.length, n - off);
			out.set(head.subarray(0, k), off);
			off += k;
			if (k === head.length) this.#chunks.shift();
			else this.#chunks[0] = head.subarray(k);
		}
		this.#length -= n;
		return out;
	}
}

/**
 * Constant-time comparison. Uses Workers' `crypto.subtle.timingSafeEqual` where it exists; elsewhere
 * an XOR fold. Unequal lengths are simply unequal.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	const subtle = crypto.subtle as SubtleCrypto & { timingSafeEqual?: (a: ArrayBufferView, b: ArrayBufferView) => boolean };
	if (typeof subtle.timingSafeEqual === "function") return subtle.timingSafeEqual(a, b);
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
	return diff === 0;
}
