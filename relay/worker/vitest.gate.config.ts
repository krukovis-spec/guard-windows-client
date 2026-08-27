import { cloudflarePool, cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const testBindings = {
  BOOTSTRAP_ADMIN_TOKEN: "test-only-bootstrap-token-8f3f0d4dd15ebd16c4f5ac14a1c9e617",
  RP_ID: "example.test",
  RP_ORIGIN: "https://example.test",
  SESSION_SECRET: "test-only-session-secret-4cc96d012553635711a0d1b5d4a3b260",
  PARENT_INVITE_SECRET: "test-only-parent-invite-174c34797fbb42d9a3e57ce5a5bcf82e",
};

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" }, miniflare: { bindings: testBindings } })],
  test: {
    pool: cloudflarePool({ wrangler: { configPath: "./wrangler.jsonc" }, miniflare: { bindings: testBindings } }),
  },
});
