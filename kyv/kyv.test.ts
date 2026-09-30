// KYV W1 spike tests: sign → verify → tamper → verify fails, plus the committed
// reference artifacts (public/.well-known/attestations.json and the first daily
// root) stay internally consistent. BUILD-PLAN-KYV W1 DoD.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  type Attestation,
  type WellKnownAttestations,
  canonicalize,
  generateIssuerKeyPair,
  isWithinValidity,
  leafHash,
  merkleProof,
  merkleRoot,
  sha256Hex,
  signAttestation,
  validateAttestation,
  validateWellKnown,
  verifyAttestationSignature,
  verifyMerkleProof,
} from "./kyv";

const LOG_START_DATE = "2026-09-30"; // cannot be backfilled — recorded in PROGRESS.md

function baseAttestation(): Attestation {
  return {
    subject: "example.test",
    issuer: "example.test",
    witness: "self",
    level: 1,
    alive_since: "2026-01-01",
    last_verified: "2026-09-30T00:00:00Z",
    continuity: { months: 8, gaps: 0 },
    valid_from: "2026-09-30T00:00:00Z",
    valid_until: "2026-10-14T00:00:00Z",
  };
}

describe("canonicalization", () => {
  it("is stable under key order and drops undefined", () => {
    expect(canonicalize({ b: 1, a: "x", c: undefined })).toBe(canonicalize({ a: "x", b: 1 }));
  });
});

describe("sign / verify / tamper", () => {
  const pair = generateIssuerKeyPair();

  it("signs and verifies", () => {
    const signed = signAttestation(baseAttestation(), pair.privateKeyPem);
    expect(verifyAttestationSignature(signed, pair.publicKeyDerB64)).toBe(true);
  });

  it("a tampered field breaks the signature", () => {
    const signed = signAttestation(baseAttestation(), pair.privateKeyPem);
    const tampered: Attestation = { ...signed, continuity: { months: 80, gaps: 0 } };
    expect(verifyAttestationSignature(tampered, pair.publicKeyDerB64)).toBe(false);
  });

  it("attaching log_inclusion does NOT break the signature (sign-then-log)", () => {
    const signed = signAttestation(baseAttestation(), pair.privateKeyPem);
    const withInclusion: Attestation = {
      ...signed,
      log_inclusion: { log: "kyv-attest/log", date: LOG_START_DATE, leaf_index: 0, proof: [] },
    };
    expect(verifyAttestationSignature(withInclusion, pair.publicKeyDerB64)).toBe(true);
  });

  it("a wrong key fails", () => {
    const signed = signAttestation(baseAttestation(), pair.privateKeyPem);
    expect(verifyAttestationSignature(signed, generateIssuerKeyPair().publicKeyDerB64)).toBe(false);
  });
});

describe("validity window", () => {
  it("inside / outside", () => {
    const a = baseAttestation();
    expect(isWithinValidity(a, new Date("2026-10-01T00:00:00Z"))).toBe(true);
    expect(isWithinValidity(a, new Date("2026-10-15T00:00:00Z"))).toBe(false);
  });
});

describe("structural validation", () => {
  it("band vocabulary rejects raw numbers", () => {
    const a: Attestation = {
      ...baseAttestation(),
      level: 2,
      bands: { grr_pct: "87" }, // raw value — non-conforming
    };
    expect(validateAttestation(a).some((e) => e.includes("band vocabulary"))).toBe(true);
    const ok: Attestation = { ...a, bands: { grr_pct: ">=85" } };
    expect(validateAttestation(ok)).toEqual([]);
  });

  it("level gates: L1 needs continuity, L0 forbids bands", () => {
    const l1 = { ...baseAttestation(), continuity: undefined };
    expect(validateAttestation(l1).some((e) => e.startsWith("continuity"))).toBe(true);
    const l0: Attestation = {
      subject: "example.test",
      issuer: "example.test",
      witness: "self",
      level: 0,
      valid_from: "2026-09-30T00:00:00Z",
      valid_until: "2026-10-14T00:00:00Z",
      bands: { mrr_usd: "<1000" },
    };
    expect(validateAttestation(l0).some((e) => e.startsWith("bands"))).toBe(true);
  });
});

describe("merkle", () => {
  const leaves = ["a", "b", "c"].map((s) => sha256Hex(s));

  it("proofs verify against the root; wrong proof fails", () => {
    const root = merkleRoot(leaves);
    for (let i = 0; i < leaves.length; i += 1) {
      expect(verifyMerkleProof(leaves[i], merkleProof(leaves, i), i, root)).toBe(true);
    }
    const badProof = merkleProof(leaves, 0).map(() => sha256Hex("nope"));
    expect(verifyMerkleProof(leaves[0], badProof, 0, root)).toBe(false);
  });
});

describe("committed reference artifacts", () => {
  const wellKnown = JSON.parse(
    readFileSync(join(process.cwd(), "public", ".well-known", "attestations.json"), "utf8"),
  ) as WellKnownAttestations;
  const rootDoc = JSON.parse(
    readFileSync(join(process.cwd(), "kyv", "log", "roots", `${LOG_START_DATE}.json`), "utf8"),
  ) as { date: string; leaf_count: number; leaves: string[]; root: string };

  it("wrapper is structurally valid", () => {
    expect(validateWellKnown(wellKnown)).toEqual([]);
  });

  it("contains the two reference formats: L1 self and L2 issuer", () => {
    const shapes = wellKnown.attestations.map((a) => `${a.level}:${a.witness}`).sort();
    expect(shapes).toEqual(["1:self", "2:issuer"]);
  });

  it("every signature verifies against the committed public key", () => {
    const keys = wellKnown.keys.map((k) => k.public_key_der_b64);
    for (const a of wellKnown.attestations) {
      expect(keys.some((k) => verifyAttestationSignature(a, k))).toBe(true);
    }
  });

  it("leaves match the committed daily root and inclusion proofs verify", () => {
    const leaves = wellKnown.attestations.map((a) => leafHash(a));
    expect(leaves).toEqual(rootDoc.leaves);
    expect(merkleRoot(leaves)).toBe(rootDoc.root);
    for (const a of wellKnown.attestations) {
      const inclusion = a.log_inclusion;
      expect(inclusion).toBeDefined();
      if (inclusion) {
        expect(inclusion.date).toBe(LOG_START_DATE);
        expect(
          verifyMerkleProof(leafHash(a), inclusion.proof, inclusion.leaf_index, rootDoc.root),
        ).toBe(true);
      }
    }
  });

  it("bands carry band vocabulary only — never raw values", () => {
    for (const a of wellKnown.attestations) {
      for (const band of Object.values(a.bands ?? {})) {
        expect(band).toMatch(/^(>=|<|\d+(\.\d+)?-)/);
      }
    }
  });
});
