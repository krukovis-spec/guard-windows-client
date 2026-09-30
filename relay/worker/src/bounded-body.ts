export class RequestBodyError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); }
}

/** Limit the actual stream, not just a client-supplied Content-Length. */
export async function readBoundedBody(request: Request, maximumBytes: number): Promise<Uint8Array<ArrayBuffer>> {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^[0-9]+$/.test(declared) || !Number.isSafeInteger(Number(declared)) || Number(declared) > maximumBytes)) {
    void request.body?.cancel().catch(() => {});
    throw new RequestBodyError(413, "request_too_large");
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const buffer = new Uint8Array(maximumBytes);
  let size = 0;
  let timedOut = false;
  const deadline = setTimeout(() => { timedOut = true; void reader.cancel().catch(() => {}); }, 20000);
  try {
    while (true) {
      const item = await reader.read();
      if (timedOut) throw new RequestBodyError(408, "request_timeout");
      if (item.done) break;
      size += item.value.byteLength;
      if (size > maximumBytes) throw new RequestBodyError(413, "request_too_large");
      buffer.set(item.value, size - item.value.byteLength);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { clearTimeout(deadline); reader.releaseLock(); }
  return buffer.slice(0, size);
}
