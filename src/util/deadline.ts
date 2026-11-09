/**
 * Runs `work`, rejecting once `ms` pass or `signal` aborts; `stop` is called then so the work's
 * connection closes (and the work itself ends) instead of running on unseen.
 */
export async function withDeadline<T>(work: () => Promise<T>, ms: number, signal: AbortSignal | undefined, what: string, stop: (e: Error) => void): Promise<T> {
	if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error(`${what}: aborted`);
	let timer: ReturnType<typeof setTimeout> | undefined;
	let onAbort: (() => void) | undefined;
	const stopped = new Promise<never>((_, reject) => {
		const fail = (e: Error) => {
			stop(e);
			reject(e);
		};
		timer = setTimeout(() => fail(new Error(`${what}: timed out after ${ms} ms`)), ms);
		onAbort = () => fail(signal?.reason instanceof Error ? signal.reason : new Error(`${what}: aborted`));
		signal?.addEventListener("abort", onAbort, { once: true });
	});
	const running = work();
	running.catch(() => {}); // its own failure after a timeout is expected and already reported
	try {
		return await Promise.race([running, stopped]);
	} finally {
		if (timer !== undefined) clearTimeout(timer);
		if (onAbort) signal?.removeEventListener("abort", onAbort);
	}
}
