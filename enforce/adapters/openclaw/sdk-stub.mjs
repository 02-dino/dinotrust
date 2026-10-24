// Resolve hook so the SELFTEST can import handler.ts directly.
//
// WHY THIS EXISTS: handler.ts imports "openclaw/plugin-sdk/plugin-entry",
// which only resolves inside a running gateway. Under a bare
// `node --experimental-strip-types selftest.mjs` that import throws, so the
// selftest used to COPY handler.ts's logic instead of importing it.
//
// That copy is the single most expensive bug source in this repo. Measured
// 2026-10-23/24: FOUR separate defects shipped green because the selftest was
// asserting against its own stale duplicate while the real adapter diverged --
// including the heredoc block that killed 7 unattended cron runs.
//
// The fix: alias the one unresolvable specifier to a no-op stub, so the test
// can import the REAL module. Only the plugin-entry wrapper is stubbed;
// every rule, regex and detector under test is the genuine article.
//
// Usage: node --experimental-strip-types --import ./sdk-stub.mjs selftest.mjs
import { register } from "node:module";
import { pathToFileURL } from "node:url";

register(
  "data:text/javascript," +
    encodeURIComponent(`
      export async function resolve(specifier, context, nextResolve) {
        if (specifier === "openclaw/plugin-sdk/plugin-entry") {
          return { url: "data:text/javascript,export const definePluginEntry=(x)=>x;export default definePluginEntry;", shortCircuit: true };
        }
        return nextResolve(specifier, context);
      }
    `),
  pathToFileURL("./"),
);
