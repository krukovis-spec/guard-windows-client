import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";
import { copyFor } from "../src/i18n";
import { runInNewContext } from "node:vm";

it("provides Russian text for every caption without dropping the English option", () => {
  const ru = copyFor("ru");
  expect(Object.keys(ru)).toEqual(Object.keys(copyFor("en")));
  for (const text of Object.values(ru)) expect(text).toMatch(/[А-Яа-яЁё]/);
  expect(ru.development).toContain("не готова");
});

it("cannot show a ready inbox or enable sign-in without the verification adapter", async () => {
  const source = await readFile(new URL("../src/main.ts", import.meta.url), "utf8");
  expect(source).toContain('if (!verifier) { state = "not-configured"; render(); return; }');
  expect(source).toContain('login.disabled = true; register.disabled = true;');
  expect(source).not.toContain("unavailableVerifier");
});

it("does not serve stale HTML or hashed scripts from the previous translation build", async () => {
  const handlers: Record<string, (event: unknown) => void> = {};
  const worker = await readFile(new URL("../public/sw.js", import.meta.url), "utf8");
  runInNewContext(worker, {
    self: { location: { origin: "https://guard.test" }, addEventListener: (name: string, handler: (event: unknown) => void) => { handlers[name] = handler; } },
    URL
  });
  for (const path of ["/", "/index.html", "/assets/index-old.js", "/v1/parent/inbox"]) {
    let intercepted = false;
    handlers.fetch!({ request: { method: "GET", url: `https://guard.test${path}` }, respondWith: () => { intercepted = true; } });
    expect(intercepted).toBe(false);
  }
});
