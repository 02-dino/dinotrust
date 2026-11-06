// Concurrency proof for the shared inbound-latch store.
//
// WHY A SEPARATE FILE: selftest.mjs is single-process, and the defect this
// guards is only observable with CONCURRENT WRITERS -- 14 gateway processes on
// this box share one latch file via os.homedir(). A single-process suite can
// assert the merge logic is correct and still ship a store that loses rows the
// moment two agents speak at once, which is exactly what happened.
//
// It reimplements the two persist strategies rather than importing handler.ts:
// the module's store path is bound inside register() and its state is private,
// so driving the real function from N processes would mean booting N gateways.
// The contract under test is the WRITE STRATEGY (truncate-in-place vs
// tmp+rename), which is reproduced here verbatim.
//
// Run: node latch-race.test.mjs
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const WRITERS = 8;        // mirrors the live fleet's order of magnitude
const ROUNDS = 150;       // enough writes to land inside a truncate window
const READER_SAMPLES = 4000;

// The child half: a writer loops persist(), a reader loops hydrate().
if (process.argv[2] === "--writer" || process.argv[2] === "--reader") {
  const [, , role, file, id] = process.argv;
  const atomic = process.env.ATOMIC === "1";

  const writeStore = (rows) => {
    if (atomic) {
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(rows));
      fs.renameSync(tmp, file);
    } else {
      fs.writeFileSync(file, JSON.stringify(rows));   // truncates in place
    }
  };

  if (role === "--writer") {
    for (let i = 0; i < ROUNDS; i++) {
      let rows = {};
      try { rows = JSON.parse(fs.readFileSync(file, "utf8")) ?? {}; } catch { /* torn/absent */ }
      rows[`agent:${id}`] = { senderId: id, tsMs: Date.now(), pad: "x".repeat(400) };
      writeStore(rows);
    }
    process.exit(0);
  }

  // Reader: hydrateLatchStore's read path. A parse failure is the dangerous
  // event -- in the real plugin it is swallowed and every foreign row reads as
  // gone, which is an owner silently demoted to non-owner.
  let torn = 0, ok = 0;
  for (let i = 0; i < READER_SAMPLES; i++) {
    try { JSON.parse(fs.readFileSync(file, "utf8")); ok++; } catch { torn++; }
  }
  process.stdout.write(JSON.stringify({ torn, ok }));
  process.exit(0);
}

// ── parent ──────────────────────────────────────────────────────────────────
const run = (args, env) => new Promise((res) => {
  let out = "";
  const p = spawn(process.execPath, [process.argv[1], ...args], {
    env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "inherit"],
  });
  p.stdout.on("data", (d) => { out += d; });
  p.on("exit", () => res(out));
});

async function trial(atomic) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "latch-race-")), "latch.json");
  fs.writeFileSync(file, "{}");
  const env = { ATOMIC: atomic ? "1" : "0" };
  const reader = run(["--reader", file, "r"], env);
  await Promise.all([
    ...Array.from({ length: WRITERS }, (_, i) => run(["--writer", file, `w${i}`], env)),
    reader,
  ]);
  const { torn, ok } = JSON.parse(await reader);
  const survivors = Object.keys(JSON.parse(fs.readFileSync(file, "utf8"))).length;
  fs.rmSync(path.dirname(file), { recursive: true, force: true });
  return { torn, ok, survivors };
}

const naive = await trial(false);
const atomic = await trial(true);
console.log(`naive  (writeFileSync): torn reads ${naive.torn}/${naive.torn + naive.ok}, agents surviving ${naive.survivors}/${WRITERS}`);
console.log(`atomic (tmp+rename)   : torn reads ${atomic.torn}/${atomic.torn + atomic.ok}, agents surviving ${atomic.survivors}/${WRITERS}`);

let failed = 0;
const check = (name, cond) => { console.log(`${cond ? "PASS" : "FAIL"}  ${name}`); if (!cond) failed++; };
// The ONLY hard assertion. The naive leg is diagnostic, not a gate: the race is
// timing-dependent, so demanding it fail would make this suite flaky on a quiet
// box -- a test that must observe a bug to pass is worse than no test.
check("atomic write is never observed torn by a concurrent reader", atomic.torn === 0);
check("atomic write preserves every agent's row under concurrency", atomic.survivors === WRITERS);
if (naive.torn === 0) console.log("NOTE  naive leg did not tear this run (timing-dependent); atomic assertions still hold");

console.log(failed === 0 ? "\nlatch-race: all passed" : `\nlatch-race: ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
