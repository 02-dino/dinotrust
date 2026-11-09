import { recordInbound, peekInbound, noteRunTrigger, runMayAdopt } from "./handler.ts";
let fail = 0; const ok = (n, c) => { console.log((c ? "PASS " : "FAIL ") + n); if (!c) fail++; };
const SK = "agent:analyst:telegram:group:-100:topic:9";
const msg = () => ({ text: "yes delete", replyToId: null, senderId: "111", tsMs: Date.now(), runId: null });
// 1. the 2026-11-09 race: memory run peeks first, then the owner's user run
recordInbound(SK, msg());
noteRunTrigger("memRun", "memory"); noteRunTrigger("userRun", "user");
let d = {}; ok("memory run cannot adopt", peekInbound(SK, "111", "memRun", d) === null && d.reason === "non_user_run");
ok("user run still adopts after memory peek", peekInbound(SK, "111", "userRun")?.text === "yes delete");
d = {}; ok("other run sees run_mismatch + owner", peekInbound(SK, "111", "x", d) === null && d.reason === "run_mismatch" && d.ownerRunId === "userRun");
// 2. unknown trigger = old behaviour (no widening, no regression)
recordInbound(SK + "b", msg());
ok("unknown-trigger run adopts (legacy)", runMayAdopt("never-seen") && peekInbound(SK + "b", "111", "never-seen") != null);
// 3. diagnostics
d = {}; peekInbound("agent:a:telegram:direct:none", "111", "userRun", d); ok("no_row", d.reason === "no_row");
recordInbound(SK + "c", msg()); d = {}; peekInbound(SK + "c", "222", "userRun", d); ok("sender_mismatch", d.reason === "sender_mismatch");
recordInbound(SK + "d", { ...msg(), tsMs: Date.now() - 121000 }); d = {}; peekInbound(SK + "d", "111", "userRun", d); ok("expired_ttl", d.reason === "expired_ttl");
ok("manual allowed, heartbeat/cron denied", runMayAdopt((noteRunTrigger("m","manual"),"m")) && !runMayAdopt((noteRunTrigger("h","heartbeat"),"h")) && !runMayAdopt((noteRunTrigger("c","cron"),"c")));
console.log(fail ? `latchclaim: ${fail} FAILED` : "latchclaim: all passed"); process.exit(fail ? 1 : 0);
