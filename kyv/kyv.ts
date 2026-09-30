// KYV (kyv-attest) reference implementation — core library. W1 spike.
// Spec skeleton: docs/KYV-SPEC-DRAFT.md · scope: docs/UNFREEZE-MEMO-KYV.md §2.
//
// Signing rule (sign-then-log): the Ed25519 signature covers the canonical JSON
// of the attestation WITHOUT `signature` and WITHOUT `log_inclusion`. The daily
// Merkle leaf commits to the SIGNED document minus `log_inclusion`, which is
// attached only after the day's root exists.
// Bands only, never raw values (spec §7) — enforced structurally here.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";

export type Witness = "observed" | "self" | "issuer";
export type Level = 0 | 1 | 2 | 3;

export interface Continuity {
  months: number;
  gaps: number;
}

export interface LogInclusion {
  log: string; // e.g. "kyv-attest/log"
  date: string; // YYYY-MM-DD of the daily root
  leaf_index: number;
  proof: string[]; // sibling hashes (hex), leaf → root order
}

export interface Attestation {
  subject: string;
  issuer: string;
  witness: Witness;
  level: Level;
  alive_since?: string;
  last_verified?: string;
  continuity?: Continuity;
  bands?: Record<string, string>;
  valid_from: string;
  valid_until: string;
  log_inclusion?: LogInclusion;
  signature?: string; // base64 Ed25519, see signing rule above
}

export interface WellKnownKey {
  id: string;
  alg: "Ed25519";
  public_key_der_b64: string;
}

export interface WellKnownAttestations {
  kyv: "0";
  subject: string;
  keys: WellKnownKey[];
  attestations: Attestation[];
}

const WITNESSES: readonly string[] = ["observed", "self", "issuer"];
// Spec §7 band vocabulary: ">=N", "<N", "N-M" (integers or decimals).
const BAND_RE = /^(>=\d+(\.\d+)?|<\d+(\.\d+)?|\d+(\.\d+)?-\d+(\.\d+)?)$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Deterministic JSON: recursively sorted object keys, no whitespace.
// (JCS-lite; the W1 spec prose pins exact canonicalization.)
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (isRecord(value)) {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
  }
  throw new Error(`canonicalize: unsupported value of type ${typeof value}`);
}

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function stripped(a: Attestation, drop: readonly (keyof Attestation)[]): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...a };
  for (const key of drop) delete copy[key];
  return copy;
}

/** Bytes the Ed25519 signature covers. */
export function signingPayload(a: Attestation): string {
  return canonicalize(stripped(a, ["signature", "log_inclusion"]));
}

/** Bytes the daily Merkle leaf covers (the signed doc, minus log_inclusion). */
export function leafPayload(a: Attestation): string {
  return canonicalize(stripped(a, ["log_inclusion"]));
}

export function leafHash(a: Attestation): string {
  return sha256Hex(leafPayload(a));
}

// ---------------------------------------------------------------- validation

export function validateAttestation(v: unknown): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return ["attestation must be an object"];
  const a = v;
  for (const field of ["subject", "issuer", "valid_from", "valid_until"] as const) {
    if (typeof a[field] !== "string" || a[field] === "") errors.push(`${field}: required string`);
  }
  if (!WITNESSES.includes(a.witness as string)) errors.push("witness: must be observed|self|issuer");
  const level = a.level;
  if (typeof level !== "number" || ![0, 1, 2, 3].includes(level)) {
    errors.push("level: must be 0|1|2|3");
    return errors;
  }
  if (a.witness === "self" && a.subject !== a.issuer) {
    errors.push("witness self: issuer must equal subject");
  }
  if (level >= 1) {
    if (typeof a.alive_since !== "string" || !DATE_RE.test(a.alive_since)) {
      errors.push("alive_since: required YYYY-MM-DD at level >= 1");
    }
    if (typeof a.last_verified !== "string") errors.push("last_verified: required at level >= 1");
    const c = a.continuity;
    if (
      !isRecord(c) ||
      typeof c.months !== "number" ||
      typeof c.gaps !== "number" ||
      c.months < 0 ||
      c.gaps < 0
    ) {
      errors.push("continuity: required {months>=0, gaps>=0} at level >= 1");
    }
  }
  if (level >= 2) {
    const bands = a.bands;
    if (!isRecord(bands) || Object.keys(bands).length === 0) {
      errors.push("bands: required non-empty object at level >= 2");
    } else {
      for (const [metric, band] of Object.entries(bands)) {
        if (typeof band !== "string" || !BAND_RE.test(band)) {
          // Never echo the offending value — a raw number must not survive
          // into any output, error messages included (bands-only rule).
          errors.push(`bands.${metric}: value is not band vocabulary (>=N | <N | N-M)`);
        }
      }
    }
  }
  if (level < 2 && a.bands !== undefined) {
    errors.push("bands: not allowed below level 2");
  }
  return errors;
}

export function validateWellKnown(v: unknown): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return ["document must be an object"];
  if (v.kyv !== "0") errors.push('kyv: must be "0"');
  if (typeof v.subject !== "string" || v.subject === "") errors.push("subject: required string");
  if (!Array.isArray(v.keys) || v.keys.length === 0) errors.push("keys: required non-empty array");
  if (!Array.isArray(v.attestations)) {
    errors.push("attestations: required array");
    return errors;
  }
  v.attestations.forEach((a, i) => {
    for (const e of validateAttestation(a)) errors.push(`attestations[${i}].${e}`);
    if (isRecord(a) && typeof v.subject === "string" && a.subject !== v.subject) {
      errors.push(`attestations[${i}].subject: must match document subject`);
    }
  });
  return errors;
}

// ------------------------------------------------------------------- signing

export interface IssuerKeyPair {
  privateKeyPem: string;
  publicKeyDerB64: string;
}

export function generateIssuerKeyPair(): IssuerKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyDerB64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  };
}

export function publicKeyFromDerB64(b64: string): KeyObject {
  return createPublicKey({ key: Buffer.from(b64, "base64"), type: "spki", format: "der" });
}

export function signAttestation(a: Attestation, privateKeyPem: string): Attestation {
  const key = createPrivateKey(privateKeyPem);
  const signature = nodeSign(null, Buffer.from(signingPayload(a), "utf8"), key).toString("base64");
  return { ...a, signature };
}

export function verifyAttestationSignature(a: Attestation, publicKeyDerB64: string): boolean {
  if (typeof a.signature !== "string" || a.signature === "") return false;
  return nodeVerify(
    null,
    Buffer.from(signingPayload(a), "utf8"),
    publicKeyFromDerB64(publicKeyDerB64),
    Buffer.from(a.signature, "base64"),
  );
}

/** Short-TTL validity window check (spec §8). Absence of a doc NEVER means negative. */
export function isWithinValidity(a: Attestation, at: Date): boolean {
  const from = Date.parse(a.valid_from);
  const until = Date.parse(a.valid_until);
  if (Number.isNaN(from) || Number.isNaN(until)) return false;
  const t = at.getTime();
  return t >= from && t <= until;
}

// -------------------------------------------------------------------- merkle

function pairHash(left: string, right: string): string {
  return sha256Hex(Buffer.concat([Buffer.from(left, "hex"), Buffer.from(right, "hex")]));
}

/** Root over hex leaves; odd node count duplicates the last node (CT-style). */
export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return sha256Hex("");
  let layer = [...leaves];
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(pairHash(left, right));
    }
    layer = next;
  }
  return layer[0];
}

/** Sibling path (leaf → root) for `index`. */
export function merkleProof(leaves: string[], index: number): string[] {
  if (index < 0 || index >= leaves.length) throw new Error("merkleProof: index out of range");
  const proof: string[] = [];
  let layer = [...leaves];
  let idx = index;
  while (layer.length > 1) {
    const sibling = idx % 2 === 0 ? Math.min(idx + 1, layer.length - 1) : idx - 1;
    proof.push(layer[sibling]);
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(pairHash(left, right));
    }
    layer = next;
    idx = Math.floor(idx / 2);
  }
  return proof;
}

export function verifyMerkleProof(
  leaf: string,
  proof: string[],
  index: number,
  root: string,
): boolean {
  let hash = leaf;
  let idx = index;
  for (const sibling of proof) {
    hash = idx % 2 === 0 ? pairHash(hash, sibling) : pairHash(sibling, hash);
    idx = Math.floor(idx / 2);
  }
  return hash === root;
}
