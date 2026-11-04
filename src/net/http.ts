import { ByteQueue, concat, dec, enc } from "../util/bytes.js";
import { userAgent } from "../runtime.js";
import { TlsSocket } from "./tls.js";

export type HttpResponse = { status: number; headers: Headers; body: Uint8Array };

const CRLF = enc.encode("\r\n");
const HEAD_END = enc.encode("\r\n\r\n");

export function formatRequestHead(method: string, host: string, path: string, headers: Record<string, string>): Uint8Array {
	let head = `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\n`;
	for (const [k, v] of Object.entries(headers)) {
		if (/[\r\n]/.test(k + v)) throw new Error("HTTP: header contains a line break");
		head += `${k}: ${v}\r\n`;
	}
	return enc.encode(head + "\r\n");
}

export async function readResponseHead(q: ByteQueue): Promise<{ status: number; headers: Headers }> {
	const lines = dec.decode(await q.takeThrough(HEAD_END)).split("\r\n");
	const m = /^HTTP\/1\.[01] (\d{3})/.exec(lines[0] ?? "");
	if (!m) throw new Error(`HTTP: bad status line ${JSON.stringify(lines[0])}`);
	const headers = new Headers();
	for (const line of lines.slice(1)) {
		const i = line.indexOf(":");
		if (i > 0) headers.append(line.slice(0, i).trim(), line.slice(i + 1).trim());
	}
	return { status: Number(m[1]), headers };
}

async function readBody(q: ByteQueue, headers: Headers): Promise<Uint8Array> {
	if (headers.get("transfer-encoding")?.toLowerCase().includes("chunked")) {
		const parts: Uint8Array[] = [];
		for (;;) {
			const size = parseInt(dec.decode(await q.takeThrough(CRLF)), 16);
			if (Number.isNaN(size)) throw new Error("HTTP: bad chunk size");
			if (size === 0) break;
			parts.push(await q.take(size));
			await q.take(2);
		}
		return concat(...parts);
	}
	const len = headers.get("content-length");
	return len != null ? q.take(Number(len)) : q.rest();
}

/**
 * One HTTPS request to a Signal host over our own TLS (fetch() can't verify Signal's CA).
 * Opens a fresh connection per request; fine for the handful of REST calls we make.
 */
export async function signalFetch(
	host: string,
	method: string,
	path: string,
	opts: { headers?: Record<string, string>; json?: unknown; body?: Uint8Array } = {},
): Promise<HttpResponse> {
	const body = opts.json !== undefined ? enc.encode(JSON.stringify(opts.json)) : opts.body;
	const headers: Record<string, string> = {
		"User-Agent": userAgent(),
		Connection: "close",
		...(opts.json !== undefined ? { "Content-Type": "application/json" } : {}),
		...opts.headers,
		"Content-Length": String(body?.length ?? 0),
	};
	const sock = await TlsSocket.connect(host);
	try {
		// A server may answer (e.g. 401/413) and close before reading the whole body;
		// then the write fails but the response is still waiting to be read.
		let writeError: unknown;
		try {
			await sock.write(formatRequestHead(method, host, path, headers));
			if (body?.length) await sock.write(body);
		} catch (e) {
			console.warn(`signalFetch ${method} ${path}: write failed after head, reading response anyway:`, String(e));
			writeError = e;
		}
		const q = new ByteQueue(sock.readable);
		const head = await readResponseHead(q).catch((e) => {
			throw writeError ?? e;
		});
		const resBody = method === "HEAD" || head.status === 204 ? new Uint8Array(0) : await readBody(q, head.headers);
		return { ...head, body: resBody };
	} finally {
		await sock.close();
	}
}
