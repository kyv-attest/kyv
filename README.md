# kyv-attest — Know Your Vendor

Signed, banded, machine-verifiable operational facts about a company, published at its own
`/.well-known/attestations.json`. Ed25519-signed, offline-verifiable, anchored in a daily
transparency log. **Facts only — no rankings, no scores. Absence never means negative.**

Payments for AI agents have a foundation (x402). Agent identity has one (ANS). Nobody answers
the remaining question: *is the company on the other end of the pipe real — and continuously
real?* This repo is a small convention for that layer, plus a reference implementation and the
benchmark that motivated its design.

## GhostBench: why reachability is not the signal

We collected 20 verifiably shut-down SaaS products (shutdown-evidence URL per entry) and 6
alive controls, then asked models about each as if picking a vendor
(`kyv/ghostbench/`, re-runnable):

- **19 of 20 dead products' domains still answer.** Re-measured 2026-10-09 with
  redirects not followed: five bare 200s, thirteen redirects, one 503, one no
  response at all. Most hand you to an acquirer or a farewell page. The web will
  not tell you a company died.
- A frontier model (Claude Opus 4.8) flagged **20/20** dead with no tools — famous shutdowns
  are in the weights. (Documented bias: requiring verifiable death skews the set famous;
  real exposure is the long tail and post-cutoff shutdowns.)
- The small/fast model class that actually runs inside agent loops (Claude Haiku 4.5)
  presented **8/20** dead vendors as sign-up-today viable — and a facts-only verification
  result rescued 3 while **newly breaking 2**: it read `https_reachable: true` as proof of
  life. Weak facts can be worse than no facts.

The signal that separates a live vendor from a ghost is **signed, continuously renewed
aliveness** — `alive_since` + `continuity`, where a missed day in the log is a visible gap.
That is Level 1 of this convention.

## The convention in one glance

| Level | Content | Cost to publish |
|---|---|---|
| 0 | domain + public key | one DNS TXT or one file, ~5 min |
| 1 | aliveness + continuity (no financials) | near zero |
| 2 | banded financials (e.g. `"grr_pct": ">=85"`) | bands only, never raw |
| 3 | retention depth (cohort bands) | |

Witness states: `observed` (mechanical facts a verifier gathers — the default) / `self`
(domain holder signs; the log witnesses continuity) / `issuer` (a third party verified
read-only payment data). **Multiple issuers are welcome — the spec and the log are the root
of trust, not any single key.** Full draft: [SPEC.md](SPEC.md).

## Use it as an MCP server

No clone, no build, no API key. The package has **zero runtime dependencies** —
only Node built-ins — which is the point: a tool that tells you whether to trust
someone else should not ask you to trust a dependency tree.

```jsonc
// Claude Desktop / Claude Code / any MCP client
{
  "mcpServers": {
    "kyv": { "command": "npx", "args": ["-y", "kyv-attest-mcp"] }
  }
}
```

It exposes one tool, `verify(domain)`. It returns what the domain publishes and
what can be observed about it, and nothing else: no ranking, no score, no
recommendation, and no inference from absence.

```bash
npx -y kyv-attest verify ./attestations.json   # the CLI, same package
```

## Quickstart (from source)

```bash
npm install         # or pnpm install

# verify a domain's published attestations + observed facts (offline except the fetches)
npx tsx kyv/preflight.ts example.com

# run it as an MCP server exposing verify(domain)
npx tsx kyv/mcp-server.ts

# OpenAI-style tool schema
cat kyv/openai-tool.json

# publish your own: generate a key, sign an attestation
npx tsx kyv/cli.ts keygen
npx tsx kyv/cli.ts sign your-attestation.json

# re-run the benchmark (needs ANTHROPIC_API_KEY)
npx tsx kyv/ghostbench/run.ts --model claude-opus-4-8

npm test
```

## The first entry is unflattering on purpose

The reference issuer's own attestation (`public/.well-known/attestations.json`) reads
`mrr_usd: "<1000"`. The transparency log started 2026-09-30 and history cannot be backfilled,
so the continuity is however old the log is and no older. A verification convention that
starts by flattering its author isn't one.

It has already failed once in public: the document sat nine days stale and five from expiry
while ten consecutive daily roots came out bit-identical, because nothing had re-signed it.
Stamping was compounding; continuity was not. That is the failure mode this convention exists
to make visible, and it was visible.

Transparency log: daily Merkle roots + OpenTimestamps receipts live in
[`kyv-attest/log`](https://github.com/kyv-attest/log).

## Guardrails (load-bearing, not decoration)

- Bands only, never raw values — non-conforming documents are reported invalid and never rendered.
- `null` / absence NEVER means negative. Absence is non-adoption, not a signal.
- No rankings, no scores, no leaderboards — a credential layer must judge nothing.
- Verifier consumers: `observed` ≠ `attested`; `https_reachable` only means the domain served
  a response — parked and farewell pages do too.

## Status

v0 draft. Feedback wanted on the band vocabulary (SPEC §7) and on what an agent runtime would
need before calling `verify(domain)` by default. MIT.
