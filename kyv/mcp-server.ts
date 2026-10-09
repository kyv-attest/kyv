// KYV W2 — MCP server skin. Hand-rolled stdio JSON-RPC (newline-delimited),
// no SDK dependency — same culture as lib/github/client.ts (no Octokit).
//
// Run: pnpm kyv:mcp   (or: tsx kyv/mcp-server.ts)
// Register in a runtime as a stdio server; it exposes ONE tool:
//   verify(domain) → the canonical kyv verify JSON (kyv/verify-core.ts) —
//   facts only, bands only, no ranking; absence never means negative.

import { createInterface } from "node:readline";
import { ABSENCE_NOTE, isValidPublicDomain, verifyDomain } from "./verify-core";

const PROTOCOL_VERSION = "2025-06-18";

interface RpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

interface RpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: { code: number; message: string };
}

const TOOL_DEFINITION = {
  name: "verify",
  description:
    `Fetch signed, banded, machine-verifiable operational facts about a company domain ` +
    `(the kyv-attest convention: /.well-known/attestations.json), plus mechanical observed ` +
    `facts (HTTPS reachability, first CT certificate, RDAP registration, first Wayback ` +
    `capture). ${ABSENCE_NOTE}`,
  inputSchema: {
    type: "object",
    properties: {
      domain: {
        type: "string",
        description: "Public domain to verify, e.g. example.com",
      },
    },
    required: ["domain"],
  },
} as const;

type VerifyFn = typeof verifyDomain;

export async function handleRpc(
  request: RpcRequest,
  verify: VerifyFn = verifyDomain,
): Promise<RpcResponse | null> {
  const id = request.id ?? null;
  switch (request.method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: "kyv-attest", version: "0.1.0" },
        },
      };
    case "notifications/initialized":
      return null; // notification — no response
    case "ping":
      return { jsonrpc: "2.0", id, result: {} };
    case "tools/list":
      return { jsonrpc: "2.0", id, result: { tools: [TOOL_DEFINITION] } };
    case "tools/call": {
      const params = request.params ?? {};
      const name = params.name;
      if (name !== "verify") {
        return { jsonrpc: "2.0", id, error: { code: -32602, message: `unknown tool: ${String(name)}` } };
      }
      const args = (params.arguments ?? {}) as Record<string, unknown>;
      const domain = typeof args.domain === "string" ? args.domain : "";
      if (!isValidPublicDomain(domain)) {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: `not a valid public domain: ${domain}` }],
            isError: true,
          },
        };
      }
      try {
        const result = await verify(domain);
        return {
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: JSON.stringify(result) }] },
        };
      } catch (err) {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: `verify failed: ${err instanceof Error ? err.message : "unknown error"}` }],
            isError: true,
          },
        };
      }
    }
    default:
      if (id === null) return null; // unknown notification — ignore
      return { jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${request.method}` } };
  }
}

function main(): void {
  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (trimmed === "") return;
    void (async () => {
      let parsed: RpcRequest;
      try {
        parsed = JSON.parse(trimmed) as RpcRequest;
      } catch {
        process.stdout.write(
          `${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } })}\n`,
        );
        return;
      }
      const response = await handleRpc(parsed);
      if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
    })();
  });
}

// Only start the stdio loop when executed directly, not when imported by tests.
// Match either extension: under tsx the entry is mcp-server.ts, in a published
// build it is dist/mcp-server.js. Checking only ".ts" made every compiled
// build a silent no-op — it started, read nothing, and exited 0.
if (/[/\\]mcp-server\.(ts|js)$/.test(process.argv[1] ?? "")) {
  main();
}
