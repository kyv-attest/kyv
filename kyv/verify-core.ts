// KYV W2 — the shared verify(domain) core behind every skin (bare HTTP GET,
// MCP server, OpenAI tool, procurement pre-flight). One canonical JSON result
// shape for all skins (BUILD-PLAN-KYV W2: 回同一 JSON).
//
// Two halves, both judgement-free (UNFREEZE-MEMO-KYV §2/§4):
//   attested — the domain's own /.well-known/attestations.json. Signatures are
//              checked against the keys the document itself publishes (TOFU —
//              whether to trust an issuer is the consumer's decision, reported,
//              never decided here). Validity window checked; inclusion-proof
//              presence reported (full proof check needs the log's root files).
//   observed — lazy mechanical facts only: HTTPS reachability, first TLS
//              certificate in CT logs (crt.sh), RDAP registration date,
//              first Wayback capture. Facts or null. Never a judgement.
//
// SSRF posture: subject-controlled URLs (the domain's own pages) are fetched
// with redirect:"manual" and never followed; only the three fixed third-party
// APIs (crt.sh, rdap.org, web.archive.org) may follow redirects. Hostnames
// pass a strict public-domain syntax check first.
// Absence NEVER means negative (spec §11) — every result carries the note.

import { lookup } from "node:dns/promises";
import {
  type Attestation,
  type Continuity,
  type Level,
  type WellKnownAttestations,
  type Witness,
  isWithinValidity,
  validateWellKnown,
  verifyAttestationSignature,
} from "./kyv";

// The reachability caveat earned its place empirically: GhostBench showed a
// small model reading "https_reachable: true" as evidence a shut-down vendor
// was alive (parked/farewell pages also serve 200s). Weak facts can mislead;
// say so in-band.
export const ABSENCE_NOTE =
  "Facts only — no ranking, score, or recommendation. Absence of an attestation NEVER means negative: absence is non-adoption, not a signal. Observed facts are mechanical; https_reachable only means the domain served an HTTP response — parked and farewell pages do too, so reachability is NOT evidence the vendor is operating.";

const USER_AGENT = "kyv-attest/0.1 (+https://foundr.ventures)";
const WELL_KNOWN_MAX_BYTES = 262_144;
const FETCH_TIMEOUT_MS = 4_000;

export type FetchLike = typeof fetch;

export interface AttestationSummary {
  issuer: string;
  witness: Witness;
  level: Level;
  signature_valid: boolean;
  within_validity: boolean;
  alive_since?: string;
  last_verified?: string;
  continuity?: Continuity;
  bands?: Record<string, string>;
  log_inclusion_present: boolean;
}

export interface AttestedResult {
  found: boolean;
  document_valid?: boolean;
  errors?: string[];
  attestations?: AttestationSummary[];
}

export interface ObservedResult {
  https_reachable: boolean | null;
  https_status: number | null;
  ct_first_certificate: string | null;
  rdap_registered: string | null;
  wayback_first_capture: string | null;
}

export interface VerifyResult {
  kyv: "0";
  domain: string;
  checked_at: string;
  attested: AttestedResult;
  observed: ObservedResult | null;
  note: string;
}

// Strict public-hostname syntax: lowercase labels, at least two, alpha TLD.
// Rejects IP literals, single labels, and internal-looking suffixes. This is
// a syntax gate, not a resolution gate — full SSRF hardening (IP pinning) is
// a pre-deploy item, noted in BUILD-PLAN.
const HOSTNAME_RE =
  /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const BLOCKED_SUFFIXES = [".local", ".localhost", ".internal", ".home.arpa"];

export function isValidPublicDomain(input: string): boolean {
  const d = input.trim().toLowerCase();
  if (!HOSTNAME_RE.test(d)) return false;
  if (d === "localhost") return false;
  if (BLOCKED_SUFFIXES.some((s) => d.endsWith(s))) return false;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(d)) return false;
  return true;
}

// --- SSRF hardening (pre-deploy item): resolve-then-reject private ranges ---
// A hostname that RESOLVES to private/reserved space is refused before any
// fetch. Residual TOCTOU (DNS rebinding between check and fetch) is documented
// and accepted for this endpoint class; full mitigation would require pinning
// the connection to the checked address with a custom dialer.

export type ResolveLike = (hostname: string) => Promise<string[]>;

const defaultResolve: ResolveLike = async (hostname) => {
  const results = await lookup(hostname, { all: true, verbatim: true });
  return results.map((r) => r.address);
};

export function isPrivateOrReservedIp(ip: string): boolean {
  const v4 = ip.toLowerCase().startsWith("::ffff:") ? ip.slice(7) : ip;
  const m = v4.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && (b === 168 || b === 0)) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 198 && (b === 18 || b === 19 || b === 51)) return true; // bench + TEST-NET-2
    if (a === 203 && b === 0) return true; // TEST-NET-3 (over-broad by design)
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return true;
  return lower.startsWith("fe80") || lower.startsWith("fc") || lower.startsWith("fd");
}

export async function assertResolvesPublic(domain: string, resolve: ResolveLike): Promise<void> {
  let addresses: string[];
  try {
    addresses = await resolve(domain);
  } catch {
    throw new Error(`domain does not resolve: ${domain}`);
  }
  if (addresses.length === 0 || addresses.some(isPrivateOrReservedIp)) {
    throw new Error(`domain resolves to a private or reserved address: ${domain}`);
  }
}

function timeoutSignal(ms: number): AbortSignal | undefined {
  return typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(ms) : undefined;
}

async function safeFetch(
  fetchImpl: FetchLike,
  url: string,
  followRedirects: boolean,
): Promise<Response | null> {
  try {
    return await fetchImpl(url, {
      redirect: followRedirects ? "follow" : "manual",
      headers: { "user-agent": USER_AGENT, accept: "application/json, text/html;q=0.5" },
      signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
  } catch {
    return null;
  }
}

function summarize(a: Attestation, keys: string[], now: Date): AttestationSummary {
  return {
    issuer: a.issuer,
    witness: a.witness,
    level: a.level,
    signature_valid: keys.some((k) => verifyAttestationSignature(a, k)),
    within_validity: isWithinValidity(a, now),
    alive_since: a.alive_since,
    last_verified: a.last_verified,
    continuity: a.continuity,
    bands: a.bands,
    log_inclusion_present: a.log_inclusion !== undefined,
  };
}

export async function fetchAttested(
  domain: string,
  fetchImpl: FetchLike,
  now: Date,
): Promise<AttestedResult> {
  const res = await safeFetch(
    fetchImpl,
    `https://${domain}/.well-known/attestations.json`,
    false, // subject-controlled: never follow redirects
  );
  if (!res || res.status !== 200) return { found: false };
  let text: string;
  try {
    text = await res.text();
  } catch {
    return { found: false };
  }
  if (text.length > WELL_KNOWN_MAX_BYTES) {
    return { found: true, document_valid: false, errors: ["document exceeds size cap"] };
  }
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return { found: true, document_valid: false, errors: ["not valid JSON"] };
  }
  const errors = validateWellKnown(doc);
  if (errors.length > 0) {
    // Invalid documents (including raw, non-band values) are never rendered —
    // the bands-only rule survives end to end.
    return { found: true, document_valid: false, errors };
  }
  const wk = doc as WellKnownAttestations;
  const keys = wk.keys.map((k) => k.public_key_der_b64);
  return {
    found: true,
    document_valid: true,
    attestations: wk.attestations.map((a) => summarize(a, keys, now)),
  };
}

function isoDateOrNull(value: unknown): string | null {
  if (typeof value !== "string") return null;
  // Take a literal leading date when present — Date.parse would interpret a
  // timezone-less string in LOCAL time and shift the date on non-UTC machines.
  const literal = value.match(/^(\d{4}-\d{2}-\d{2})/);
  if (literal) return literal[1];
  const t = Date.parse(value);
  if (Number.isNaN(t)) return null;
  return new Date(t).toISOString().slice(0, 10);
}

async function observeHttps(
  domain: string,
  fetchImpl: FetchLike,
): Promise<{ reachable: boolean | null; status: number | null }> {
  const res = await safeFetch(fetchImpl, `https://${domain}/`, false);
  if (!res) return { reachable: false, status: null };
  return { reachable: true, status: res.status };
}

async function observeCt(domain: string, fetchImpl: FetchLike): Promise<string | null> {
  const res = await safeFetch(fetchImpl, `https://crt.sh/?q=${domain}&output=json`, true);
  if (!res || res.status !== 200) return null;
  try {
    const rows = (await res.json()) as { not_before?: unknown }[];
    if (!Array.isArray(rows) || rows.length === 0) return null;
    const dates = rows
      .map((r) => isoDateOrNull(r.not_before))
      .filter((d): d is string => d !== null)
      .sort();
    return dates[0] ?? null;
  } catch {
    return null;
  }
}

async function observeRdap(domain: string, fetchImpl: FetchLike): Promise<string | null> {
  // Naive registrable domain (last two labels) — multi-part public suffixes
  // (co.uk-style) come back null; an eTLD+1 table is a W2+ refinement.
  const registrable = domain.split(".").slice(-2).join(".");
  const res = await safeFetch(fetchImpl, `https://rdap.org/domain/${registrable}`, true);
  if (!res || res.status !== 200) return null;
  try {
    const doc = (await res.json()) as {
      events?: { eventAction?: unknown; eventDate?: unknown }[];
    };
    const registration = doc.events?.find((e) => e.eventAction === "registration");
    return isoDateOrNull(registration?.eventDate);
  } catch {
    return null;
  }
}

async function observeWayback(domain: string, fetchImpl: FetchLike): Promise<string | null> {
  const res = await safeFetch(
    fetchImpl,
    `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&fl=timestamp`,
    true,
  );
  if (!res || res.status !== 200) return null;
  try {
    const rows = (await res.json()) as unknown[][];
    const ts = rows?.[1]?.[0];
    if (typeof ts !== "string" || ts.length < 8) return null;
    return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
  } catch {
    return null;
  }
}

export async function observeDomain(
  domain: string,
  fetchImpl: FetchLike,
): Promise<ObservedResult> {
  const [https, ct, rdap, wayback] = await Promise.all([
    observeHttps(domain, fetchImpl),
    observeCt(domain, fetchImpl),
    observeRdap(domain, fetchImpl),
    observeWayback(domain, fetchImpl),
  ]);
  return {
    https_reachable: https.reachable,
    https_status: https.status,
    ct_first_certificate: ct,
    rdap_registered: rdap,
    wayback_first_capture: wayback,
  };
}

export interface VerifyOptions {
  fetchImpl?: FetchLike;
  includeObserved?: boolean;
  now?: Date;
  resolveImpl?: ResolveLike;
}

export async function verifyDomain(
  rawDomain: string,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const domain = rawDomain.trim().toLowerCase();
  if (!isValidPublicDomain(domain)) {
    throw new Error(`not a valid public domain: ${rawDomain}`);
  }
  await assertResolvesPublic(domain, options.resolveImpl ?? defaultResolve);
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? new Date();
  const attested = await fetchAttested(domain, fetchImpl, now);
  const observed =
    options.includeObserved === false ? null : await observeDomain(domain, fetchImpl);
  return {
    kyv: "0",
    domain,
    checked_at: now.toISOString(),
    attested,
    observed,
    note: ABSENCE_NOTE,
  };
}
