// A minimal Signal linked device on Cloudflare Workers: link it with a QR code, read what arrives,
// send texts. One Durable Object holds the account; every route needs the admin token.
import { DurableObject } from "cloudflare:workers";
import { durableObjectHost, durableObjectSql, Sealer, SignalClient, type MessageRecord } from "signal-edge/workers";
import { linkCryptoSelfTest, receiverSelfTest, storeSelfTest } from "signal-edge/selftest";

type Env = {
	ACCOUNT: DurableObjectNamespace<SignalAccount>;
	ADMIN_TOKEN: string;
	STORAGE_KEY: string;
};

export class SignalAccount extends DurableObject<Env> {
	readonly client: SignalClient;

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.client = new SignalClient({
			...durableObjectHost(ctx),
			storageKey: env.STORAGE_KEY,
			deviceName: "signal-edge example",
			onMessages: (records: MessageRecord[]) => {
				for (const r of records) if (r.kind === "message" && !r.outgoing) console.log(`message in ${r.conversation}`);
			},
		});
	}

	/** Keeps the receive socket up and runs key refresh and contact sync. */
	async alarm(): Promise<void> {
		const next = await this.client.maintain();
		if (next) await this.ctx.storage.setAlarm(next);
	}

	status() {
		return { link: this.client.status(), receive: this.client.receiveStatus() };
	}

	link() {
		return this.client.startLink();
	}

	messages(limit: number, chat?: string) {
		return this.client.messages(limit, chat);
	}

	chats() {
		return this.client.chats();
	}

	send(to: string, body: string) {
		return this.client.sendText(to, body);
	}

	/** Runs the self-tests in this (scratch) instance, then wipes it. Never on the linked account. */
	async selfTest() {
		if (this.client.status().state !== "unlinked") throw new Error("refusing to run self-tests on a linked account");
		try {
			const sealer = await Sealer.fromBase64(this.env.STORAGE_KEY);
			const db = durableObjectSql(this.ctx.storage);
			return { linkCrypto: await linkCryptoSelfTest(), store: await storeSelfTest(db, sealer), receiver: await receiverSelfTest(db, sealer) };
		} finally {
			await this.ctx.storage.deleteAll();
		}
	}

	async forget() {
		await this.ctx.storage.deleteAlarm();
		return this.client.reset();
	}
}

/** Constant-time comparison (of SHA-256 digests, so lengths don't leak either). */
async function tokenMatches(given: string | null, expected: string): Promise<boolean> {
	const digest = async (s: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
	return crypto.subtle.timingSafeEqual(await digest(given ?? ""), await digest(expected));
}

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		if (!env.ADMIN_TOKEN || env.ADMIN_TOKEN.length < 32 || !(await tokenMatches(req.headers.get("Authorization"), `Bearer ${env.ADMIN_TOKEN}`))) {
			return new Response("unauthorized", { status: 401 });
		}
		const account = env.ACCOUNT.getByName("primary");
		const url = new URL(req.url);
		const route = `${req.method} ${url.pathname}`;
		try {
			switch (route) {
				case "GET /status":
					return Response.json(await account.status());
				// Returns { state: "waiting_for_scan", url: "sgnl://linkdevice?..." }: show the url as a QR code
				// and scan it in Signal (Settings → Linked devices). Poll /status until "linked".
				case "POST /link":
					return Response.json(await account.link());
				case "GET /chats":
					return Response.json(await account.chats());
				case "GET /messages":
					return Response.json(await account.messages(Number(url.searchParams.get("limit") ?? 20), url.searchParams.get("chat") ?? undefined));
				// { "to": "self" | "aci:<uuid>" | "group:<id>", "body": "..." }
				case "POST /send": {
					const { to, body } = (await req.json()) as { to: string; body: string };
					return Response.json(await account.send(to, body));
				}
				// Checks the crypto and storage on this runtime, in a throwaway Durable Object.
				case "POST /selftest":
					return Response.json(await env.ACCOUNT.getByName(`selftest-${crypto.randomUUID()}`).selfTest());
				case "POST /forget":
					return Response.json(await account.forget());
			}
			return new Response("not found", { status: 404 });
		} catch (e) {
			return Response.json({ error: String(e) }, { status: 500 });
		}
	},
} satisfies ExportedHandler<Env>;
