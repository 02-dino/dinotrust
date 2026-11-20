// WhatsApp owner identity (2026-11-20, konsultan WA group incident).
// WA hands the same person over as "+628…", "628…" or an opaque LID depending
// on the event path; exact-string compare demoted the configured owner to
// non-owner mid-turn and exec (Google Sheets writes) was refused at random.
// Run: node --experimental-strip-types --import ./sdk-stub.mjs wa-owner.test.mjs
import {
  ownerIdMatches, canonicalizeSenderId, canonicalSenderFromEvent,
  sendersEquivalent, noteWaOwnerPin, readWaOwnerPin, peekInbound,
} from "./handler.ts";
let fail = 0; const ok = (n, c) => { console.log((c ? "PASS " : "FAIL ") + n); if (!c) fail++; };
const OWNER = "+6285700000001";
const cfg = (extra = {}) => ({ ownerIds: [OWNER], agentOwners: {}, waIdentityAliases: {}, ...extra });

// 1. number-form normalisation
ok("+628 vs 628 match", ownerIdMatches("6285700000001", [OWNER]));
ok("@628 vs +628 match", ownerIdMatches("@6285700000001", [OWNER]));
ok("different number never matches", !ownerIdMatches("6285700000002", [OWNER]));
ok("empty sender never matches", !ownerIdMatches("", [OWNER]) && !ownerIdMatches("+", [OWNER]));
ok("undefined owner list is safe (no throw)", ownerIdMatches("6285700000001", undefined) === false);

// 2. LID alias
const c = cfg({ waIdentityAliases: { "99887766@lid": OWNER } });
ok("LID maps to E.164 via alias", canonicalizeSenderId("99887766@lid", c) === OWNER);
ok("LID alias is case-insensitive", canonicalizeSenderId("99887766@LID".toLowerCase(), c) === OWNER);
ok("unknown LID passes through unchanged", canonicalizeSenderId("11112222@lid", c) === "11112222@lid");
ok("senderE164 preferred over LID senderId", canonicalSenderFromEvent({ senderId: "11112222@lid", senderE164: OWNER }, cfg()) === OWNER);
ok("LID-only event resolves through alias", canonicalSenderFromEvent({ senderId: "99887766@lid" }, c) === OWNER);
ok("no alias config -> LID stays LID (not owner)", !ownerIdMatches(canonicalSenderFromEvent({ senderId: "99887766@lid" }, cfg()), [OWNER]));

// 3. latch: same person in two forms is the same sender
const SKG = "agent:konsultan:whatsapp:group:1203630@g.us";
ok("sendersEquivalent +628/628", sendersEquivalent(OWNER, "6285700000001", cfg(), SKG));
ok("sendersEquivalent LID/E164 via alias", sendersEquivalent("99887766@lid", OWNER, c, SKG));
ok("sendersEquivalent: two non-owners differ", !sendersEquivalent("6281111", "6282222", cfg(), SKG));
ok("peekInbound without cfg arg does not throw", (() => { try { peekInbound(SKG + "x", "1", "r"); return true; } catch { return false; } })());

// 4. WA owner pin: only owners, only WhatsApp channel lanes
noteWaOwnerPin(SKG, "6285700000001", cfg());
ok("owner pinned on WA group lane", readWaOwnerPin(SKG) === "6285700000001");
const SK2 = "agent:konsultan:whatsapp:group:999@g.us";
noteWaOwnerPin(SK2, "6281234567890", cfg());
ok("non-owner is NEVER pinned", readWaOwnerPin(SK2) === null);
const SKT = "agent:konsultan:telegram:group:-100";
noteWaOwnerPin(SKT, OWNER, cfg());
ok("pin is WhatsApp-only (telegram ignored)", readWaOwnerPin(SKT) === null);
const SKC = "agent:konsultan:cron:job1";
noteWaOwnerPin(SKC, OWNER, cfg());
ok("pin never on non-channel lane", readWaOwnerPin(SKC) === null);
const SKA = "agent:cs:whatsapp:group:777@g.us";
noteWaOwnerPin(SKA, OWNER, cfg({ agentOwners: { "agent:cs": ["+6289999999999"] } }));
ok("pin respects per-agent owners (konsultan owner != cs owner)", readWaOwnerPin(SKA) === null);

console.log(fail ? `wa-owner: ${fail} FAILED` : "wa-owner: all passed");
process.exit(fail ? 1 : 0);
