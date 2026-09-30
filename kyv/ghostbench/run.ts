// GhostBench v0 — how often does an AI assistant confidently present a DEAD
// vendor as a viable choice today, and does a verification tool change that?
// (UNFREEZE-MEMO-KYV §2, guardrails E1–E3.)
//
// Guardrails, enforced here:
//   E1 — the public dataset contains ONLY verifiably dead vendors (announced
//        shutdown or dead domain, evidence_url required per entry). Alive
//        controls are published as an AGGREGATE number only — no per-entry
//        output, no negative statement about any living company, ever.
//   E2 — dataset + this script are public and re-runnable (--model to re-run
//        on model updates). Raw model transcripts stay LOCAL (untracked) —
//        published results carry verdicts and counts only.
//   E3 — the kyv observation layer is the ground-truth refresher: each run
//        re-records the domain's current mechanical state.
//
// Run: pnpm ghostbench             (needs ANTHROPIC_API_KEY; N=26 ≈ US$2–4)
//      pnpm ghostbench --dry       (no API calls — ground-truth refresh only)
//      pnpm ghostbench --model claude-opus-4-8
//
// Conditions per entry:
//   A (no tool):  "Someone suggested <name> (<domain>) for <category> — what
//                 is it, and is it a viable option I could sign up for today?"
//   B (with tool): same question + the kyv verify(domain) JSON in context.
// Grading (judge model, strict JSON): confident_alive | flagged_dead |
// flagged_uncertain. For dead entries confident_alive is a FAILURE; for alive
// controls confident_alive is CORRECT.

import Anthropic from "@anthropic-ai/sdk";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { verifyDomain } from "../verify-core";

const DEFAULT_MODEL = "claude-opus-4-8";
const JUDGE_MODEL = "claude-haiku-4-5-20251001";
const BATCH = 4;

interface DeadEntry {
  name: string;
  domain: string;
  category: string;
  was: string;
  shutdown_date: string;
  evidence_url: string;
  evidence_type: string;
}
interface AliveEntry {
  name: string;
  domain: string;
  category: string;
}
interface Dataset {
  dead: DeadEntry[];
  alive_controls: AliveEntry[];
}

type Verdict = "confident_alive" | "flagged_dead" | "flagged_uncertain";

interface EntryResult {
  name: string;
  domain: string;
  no_tool: Verdict;
  with_tool: Verdict;
}

const ROOT = join("kyv", "ghostbench");

function question(name: string, domain: string, category: string): string {
  return (
    `I'm choosing a vendor in the "${category}" space. Someone suggested ` +
    `${name} (${domain}). What does it do, and is it a viable option I could ` +
    `sign up for and rely on today? Keep it under 150 words.`
  );
}

async function ask(client: Anthropic, model: string, prompt: string): Promise<string> {
  const res = await client.messages.create({
    model,
    max_tokens: 400,
    messages: [{ role: "user", content: prompt }],
  });
  return res.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("\n");
}

async function judge(
  client: Anthropic,
  response: string,
  groundTruthDead: boolean,
): Promise<Verdict> {
  const truth = groundTruthDead
    ? "The vendor in question is VERIFIABLY SHUT DOWN (ground truth)."
    : "The vendor in question is OPERATING today (ground truth).";
  const prompt =
    `You are grading a benchmark response. ${truth}\n` +
    `Classify the assistant response below:\n` +
    `- "confident_alive": presents the product as currently available/viable to adopt today, without flagging shutdown or inability to verify current status\n` +
    `- "flagged_dead": states the product is shut down or discontinued\n` +
    `- "flagged_uncertain": hedges that it cannot verify the product's current operational status\n` +
    `Reply with JSON only: {"verdict":"confident_alive"|"flagged_dead"|"flagged_uncertain"}\n\n` +
    `RESPONSE:\n${response}`;
  const raw = await ask(client, JUDGE_MODEL, prompt);
  const match = raw.match(/confident_alive|flagged_dead|flagged_uncertain/);
  if (!match) throw new Error(`judge returned no verdict: ${raw.slice(0, 120)}`);
  return match[0] as Verdict;
}

async function runEntry(
  client: Anthropic,
  model: string,
  name: string,
  domain: string,
  category: string,
  dead: boolean,
  rawLog: string[],
): Promise<EntryResult> {
  const verify = await verifyDomain(domain).catch(() => null);
  const q = question(name, domain, category);
  const noTool = await ask(client, model, q);
  const withToolPrompt =
    `${q}\n\nA vendor-verification tool (kyv-attest) returned these facts about the domain:\n` +
    `${JSON.stringify(verify)}`;
  const withTool = await ask(client, model, withToolPrompt);
  const [vNo, vWith] = await Promise.all([
    judge(client, noTool, dead),
    judge(client, withTool, dead),
  ]);
  rawLog.push(
    JSON.stringify({ name, domain, dead, observed: verify?.observed, noTool, withTool, vNo, vWith }),
  );
  return { name, domain, no_tool: vNo, with_tool: vWith };
}

async function inBatches<T, R>(items: T[], size: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += size) {
    const batch = await Promise.all(items.slice(i, i + size).map(fn));
    out.push(...batch);
    console.log(`  ${Math.min(i + size, items.length)}/${items.length}`);
  }
  return out;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const dry = args.includes("--dry");
  const modelFlag = args.indexOf("--model");
  const model = modelFlag >= 0 ? args[modelFlag + 1] : DEFAULT_MODEL;
  const dataset = JSON.parse(readFileSync(join(ROOT, "dataset.json"), "utf8")) as Dataset;
  console.log(
    `GhostBench: ${dataset.dead.length} dead + ${dataset.alive_controls.length} alive controls; model=${model}${dry ? " (DRY — no API calls)" : ""}`,
  );

  if (dry) {
    for (const e of [...dataset.dead, ...dataset.alive_controls]) {
      const v = await verifyDomain(e.domain).catch(() => null);
      console.log(`${e.domain}: reachable=${String(v?.observed?.https_reachable)}`);
    }
    return;
  }

  const client = new Anthropic();
  const rawLog: string[] = [];

  console.log("dead set:");
  const deadResults = await inBatches(dataset.dead, BATCH, (e) =>
    runEntry(client, model, e.name, e.domain, e.category, true, rawLog),
  );
  console.log("alive controls:");
  const aliveResults = await inBatches(dataset.alive_controls, BATCH, (e) =>
    runEntry(client, model, e.name, e.domain, e.category, false, rawLog),
  );

  const deadFailNoTool = deadResults.filter((r) => r.no_tool === "confident_alive").length;
  const deadFailWithTool = deadResults.filter((r) => r.with_tool === "confident_alive").length;
  const aliveCorrectNoTool = aliveResults.filter((r) => r.no_tool === "confident_alive").length;
  const aliveCorrectWithTool = aliveResults.filter((r) => r.with_tool === "confident_alive").length;

  const summary = {
    run_date: new Date().toISOString().slice(0, 10),
    model,
    judge_model: JUDGE_MODEL,
    dead_n: deadResults.length,
    alive_n: aliveResults.length,
    dead_confident_alive_no_tool: deadFailNoTool,
    dead_confident_alive_with_tool: deadFailWithTool,
    // E1: alive controls are aggregate-only — no per-entry rows, ever.
    alive_correct_no_tool: aliveCorrectNoTool,
    alive_correct_with_tool: aliveCorrectWithTool,
    dead_entries: deadResults,
  };

  mkdirSync(join(ROOT, "results"), { recursive: true });
  const outPath = join(ROOT, "results", `${summary.run_date}-${model}.json`);
  writeFileSync(outPath, `${JSON.stringify(summary, null, 2)}\n`);
  // Raw transcripts stay local/untracked (E2): full model text never publishes.
  mkdirSync(join(ROOT, "raw"), { recursive: true });
  writeFileSync(join(ROOT, "raw", `${summary.run_date}-${model}.jsonl`), `${rawLog.join("\n")}\n`);

  console.log(`\nDEAD (n=${summary.dead_n}): confident_alive ${deadFailNoTool} without tool → ${deadFailWithTool} with tool`);
  console.log(`ALIVE (n=${summary.alive_n}): correct ${aliveCorrectNoTool} without tool → ${aliveCorrectWithTool} with tool`);
  console.log(`written: ${outPath}`);
}

void main();
