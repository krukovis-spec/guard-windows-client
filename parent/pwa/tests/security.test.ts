import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const testDirectory = fileURLToPath(new URL(".", import.meta.url));
const sourceRoot = resolve(testDirectory, "../src");

async function files(path: string): Promise<string[]> {
  const entries = await readdir(path, { withFileTypes: true });
  return (await Promise.all(entries.map(async (entry) => entry.isDirectory() ? files(resolve(path, entry.name)) : [resolve(path, entry.name)]))).flat();
}

describe("PWA security boundary", () => {
  it("permits only HPKE HMAC, never approval signing, key export or browser token storage", async () => {
    const contents = await Promise.all((await files(sourceRoot)).map((file) => readFile(file, "utf8")));
    const source = contents.join("\n");
    expect(source).not.toMatch(/subtle\.(?:exportKey|wrapKey)|privateKey|approval[_ -]?secret|localStorage|sessionStorage/i);
    const signCalls = source.match(/crypto\.subtle\.sign\s*\([^\n]*/g) ?? [];
    expect(signCalls).toEqual(['crypto.subtle.sign("HMAC", key, message));']);
    const verifier = await readFile(resolve(sourceRoot, "relay-receive.ts"), "utf8");
    expect(verifier).toContain('name === "ECDSA" ? ["verify"] : []');
    const main = await readFile(resolve(sourceRoot, "main.ts"), "utf8");
    expect(main).toContain("await createViewSnapshotVerifier(enrollment)");
    expect(main).not.toContain("guardParentSnapshotVerifier");
  });

  it("can neither publish a relay frame nor finalize a signing intent", async () => {
    const contents = await Promise.all((await files(sourceRoot)).map((file) => readFile(file, "utf8")));
    const source = contents.join("\n");
    expect(source).not.toMatch(/\/v1\/mailboxes\/|\/intents\/finalize|\/frames/);
  });

  it("does not cache relay APIs or ciphertext", async () => {
    const worker = await readFile(resolve(testDirectory, "../public/sw.js"), "utf8");
    expect(worker).toContain('url.pathname.startsWith("/v1/")');
    expect(worker).not.toMatch(/cache\.put|\/v1\/parent\/inbox/);
  });
});
