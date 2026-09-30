// KYV W2 tests: the shared verify(domain) core, the MCP skin's RPC handler,
// and the pre-flight brief's judgement-free guarantee. All network mocked.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { handleRpc } from "./mcp-server";
import { renderBrief } from "./preflight";
import {
  type FetchLike,
  isPrivateOrReservedIp,
  type VerifyResult,
  isValidPublicDomain,
  observeDomain,
  verifyDomain,
} from "./verify-core";

const WELL_KNOWN = readFileSync(
  join(process.cwd(), "public", ".well-known", "attestations.json"),
  "utf8",
);
const NOW = new Date("2026-10-01T00:00:00Z"); // inside the reference validity window
const RESOLVE_PUBLIC = async (): Promise<string[]> => ["93.184.216.34"];

function makeRes(status: number, body: string): Response {
  return {
    status,
    text: async () => body,
    json: async () => JSON.parse(body) as unknown,
  } as unknown as Response;
}

function fetchRouter(routes: Record<string, Response>): FetchLike {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    const match = Object.entries(routes).find(([prefix]) => url.startsWith(prefix));
    if (!match) throw new Error(`no mock route for ${url}`);
    return match[1];
  }) as FetchLike;
}

describe("isValidPublicDomain", () => {
  it("accepts public hostnames, rejects internal/IP/single-label", () => {
    expect(isValidPublicDomain("stripe.com")).toBe(true);
    expect(isValidPublicDomain("sub.example.co")).toBe(true);
    expect(isValidPublicDomain("localhost")).toBe(false);
    expect(isValidPublicDomain("foo")).toBe(false);
    expect(isValidPublicDomain("127.0.0.1")).toBe(false);
    expect(isValidPublicDomain("db.internal")).toBe(false);
    expect(isValidPublicDomain("printer.local")).toBe(false);
  });
});

describe("verifyDomain — attested half", () => {
  it("renders the reference document with valid signatures", async () => {
    const fetchImpl = fetchRouter({
      "https://foundr.ventures/.well-known/attestations.json": makeRes(200, WELL_KNOWN),
    });
    const result = await verifyDomain("foundr.ventures", {
      fetchImpl,
      includeObserved: false,
      now: NOW,
      resolveImpl: RESOLVE_PUBLIC,
    });
    expect(result.attested.found).toBe(true);
    expect(result.attested.document_valid).toBe(true);
    expect(result.attested.attestations).toHaveLength(2);
    for (const a of result.attested.attestations ?? []) {
      expect(a.signature_valid).toBe(true);
      expect(a.within_validity).toBe(true);
      expect(a.log_inclusion_present).toBe(true);
    }
  });

  it("404 → found:false, and the note still says absence is not negative", async () => {
    const fetchImpl = fetchRouter({ "https://example.com/": makeRes(404, "") });
    const result = await verifyDomain("example.com", {
      fetchImpl,
      includeObserved: false,
      now: NOW,
      resolveImpl: RESOLVE_PUBLIC,
    });
    expect(result.attested.found).toBe(false);
    expect(result.note).toMatch(/NEVER means negative/);
  });

  it("a document with raw (non-band) values is reported invalid and never rendered", async () => {
    const doc = JSON.parse(WELL_KNOWN) as {
      attestations: { bands?: Record<string, string> }[];
    };
    doc.attestations[1].bands = { mrr_usd: "742" }; // raw value — non-conforming
    const fetchImpl = fetchRouter({
      "https://example.com/.well-known/attestations.json": makeRes(200, JSON.stringify(doc)),
    });
    const result = await verifyDomain("example.com", {
      fetchImpl,
      includeObserved: false,
      now: NOW,
      resolveImpl: RESOLVE_PUBLIC,
    });
    expect(result.attested.document_valid).toBe(false);
    expect(result.attested.attestations).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain("742");
  });

  it("a redirected well-known is not followed (SSRF posture) and counts as not found", async () => {
    const fetchImpl = fetchRouter({
      "https://example.com/.well-known/attestations.json": makeRes(301, ""),
    });
    const result = await verifyDomain("example.com", {
      fetchImpl,
      includeObserved: false,
      now: NOW,
      resolveImpl: RESOLVE_PUBLIC,
    });
    expect(result.attested.found).toBe(false);
  });
});

describe("observeDomain — mechanical facts", () => {
  it("extracts dates from CT, RDAP, and Wayback", async () => {
    const fetchImpl = fetchRouter({
      "https://example.com/": makeRes(200, "<html></html>"),
      "https://crt.sh/": makeRes(
        200,
        JSON.stringify([{ not_before: "2020-05-01T00:00:00" }, { not_before: "2019-03-02T00:00:00" }]),
      ),
      "https://rdap.org/domain/example.com": makeRes(
        200,
        JSON.stringify({ events: [{ eventAction: "registration", eventDate: "2007-05-14T04:00:00Z" }] }),
      ),
      "https://web.archive.org/cdx/": makeRes(200, JSON.stringify([["timestamp"], ["20080115000000"]])),
    });
    const observed = await observeDomain("example.com", fetchImpl);
    expect(observed.https_reachable).toBe(true);
    expect(observed.ct_first_certificate).toBe("2019-03-02");
    expect(observed.rdap_registered).toBe("2007-05-14");
    expect(observed.wayback_first_capture).toBe("2008-01-15");
  });

  it("a failing sub-fetch nulls that fact without throwing", async () => {
    const fetchImpl = fetchRouter({ "https://example.com/": makeRes(200, "") });
    const observed = await observeDomain("example.com", fetchImpl);
    expect(observed.https_reachable).toBe(true);
    expect(observed.ct_first_certificate).toBeNull();
    expect(observed.rdap_registered).toBeNull();
    expect(observed.wayback_first_capture).toBeNull();
  });
});

describe("MCP skin — handleRpc", () => {
  const stubResult: VerifyResult = {
    kyv: "0",
    domain: "example.com",
    checked_at: "2026-10-01T00:00:00.000Z",
    attested: { found: false },
    observed: null,
    note: "stub",
  };
  const stubVerify = (async () => stubResult) as typeof verifyDomain;

  it("initialize / tools list / tools call round-trip", async () => {
    const init = await handleRpc({ jsonrpc: "2.0", id: 1, method: "initialize" });
    expect(init?.result).toMatchObject({ serverInfo: { name: "kyv-attest" } });

    const list = await handleRpc({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    const tools = (list?.result as { tools: { name: string }[] }).tools;
    expect(tools.map((t) => t.name)).toEqual(["verify"]);

    const call = await handleRpc(
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "verify", arguments: { domain: "example.com" } },
      },
      stubVerify,
    );
    const content = (call?.result as { content: { type: string; text: string }[] }).content;
    expect(JSON.parse(content[0].text)).toEqual(stubResult);
  });

  it("rejects an invalid domain as a tool error", async () => {
    const call = await handleRpc(
      {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: { name: "verify", arguments: { domain: "localhost" } },
      },
      stubVerify,
    );
    expect((call?.result as { isError?: boolean }).isError).toBe(true);
  });
});

describe("pre-flight brief — judgement-free by construction", () => {
  const JUDGEMENT_WORDS =
    /\b(best|top|recommend|recommended|strong|weak|impressive|good|bad|healthy|risky|trustworthy|leading|excellent|poor)\b/i;

  it("attested + observed brief carries facts and no judgement words", async () => {
    const fetchImpl = fetchRouter({
      "https://foundr.ventures/.well-known/attestations.json": makeRes(200, WELL_KNOWN),
      "https://foundr.ventures/": makeRes(200, ""),
      "https://crt.sh/": makeRes(200, "[]"),
      "https://rdap.org/": makeRes(404, ""),
      "https://web.archive.org/": makeRes(404, ""),
    });
    const result = await verifyDomain("foundr.ventures", { fetchImpl, now: NOW, resolveImpl: RESOLVE_PUBLIC });
    const brief = renderBrief(result);
    expect(brief).toContain("mrr_usd <1000");
    expect(brief).toContain("inclusion proof present");
    expect(brief).not.toMatch(JUDGEMENT_WORDS);
  });

  it("absence renders as non-adoption, not as a negative", async () => {
    const fetchImpl = fetchRouter({ "https://example.com/": makeRes(404, "") });
    const result = await verifyDomain("example.com", {
      fetchImpl,
      includeObserved: false,
      now: NOW,
      resolveImpl: RESOLVE_PUBLIC,
    });
    const brief = renderBrief(result);
    expect(brief).toContain("Absence is non-adoption, not a signal.");
    expect(brief).not.toMatch(JUDGEMENT_WORDS);
  });
});

describe("SSRF resolve gate", () => {
  it("private and reserved ranges are flagged; public ones are not", () => {
    const priv = ["10.0.0.5", "127.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "::ffff:10.0.0.1"];
    for (const ip of priv) expect(isPrivateOrReservedIp(ip)).toBe(true);
    const pub = ["93.184.216.34", "8.8.8.8", "2606:4700::1111"];
    for (const ip of pub) expect(isPrivateOrReservedIp(ip)).toBe(false);
  });

  it("a domain resolving to private space is refused before any fetch", async () => {
    const fetchImpl = fetchRouter({}); // any fetch attempt would throw "no mock route"
    await expect(
      verifyDomain("evil.example.com", { fetchImpl, resolveImpl: async () => ["10.0.0.5"] }),
    ).rejects.toThrow(/private or reserved/);
  });

  it("a non-resolving domain is refused", async () => {
    const fetchImpl = fetchRouter({});
    await expect(
      verifyDomain("nonexistent.example.com", {
        fetchImpl,
        resolveImpl: async () => {
          throw new Error("ENOTFOUND");
        },
      }),
    ).rejects.toThrow(/does not resolve/);
  });
});
