import { cloudflarePool, cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const testBindings = { BOOTSTRAP_ADMIN_TOKEN: "test-only-bootstrap-token-8f3f0d4dd15ebd16c4f5ac14a1c9e617" };

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" }, miniflare: { bindings: testBindings } })],
  test: {
    pool: cloudflarePool({ wrangler: { configPath: "./wrangler.jsonc" }, miniflare: { bindings: testBindings } })
  }
});
