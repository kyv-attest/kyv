// KYV (kyv-attest) reference CLI. W1 spike.
//
// Run: pnpm kyv <command>
//   keygen                  create kyv/.keys/issuer.pem (gitignored) and print the public key
//   sign <unsigned.json>    sign one attestation with the issuer key, print signed JSON
//   verify <path>           verify a single attestation or a .well-known wrapper — offline,
//                           no network at all (the file is read from disk)
//   daily-root <YYYY-MM-DD> Merkle root over public/.well-known/attestations.json →
//                           kyv/log/roots/<date>.json, then write log_inclusion back
//                           into the wrapper. Prints the OpenTimestamps one-liner.
//
// The private key never enters the repo: kyv/.keys/ is gitignored; in CI it comes
// from a secret. Exit codes: 0 ok, 1 verification/validation failure, 2 usage.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  type Attestation,
  type WellKnownAttestations,
  generateIssuerKeyPair,
  isWithinValidity,
  leafHash,
  merkleProof,
  merkleRoot,
  signAttestation,
  validateAttestation,
  validateWellKnown,
  verifyAttestationSignature,
  verifyMerkleProof,
} from "./kyv";

const KEY_PATH = join("kyv", ".keys", "issuer.pem");
const WELL_KNOWN_PATH = join("public", ".well-known", "attestations.json");
const LOG_NAME = "kyv-attest/log";

function fail(message: string, code: 1 | 2): never {
  console.error(`kyv: ${message}`);
  process.exit(code);
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function isWrapper(doc: unknown): doc is WellKnownAttestations {
  return typeof doc === "object" && doc !== null && "attestations" in doc;
}

function cmdKeygen(): void {
  if (existsSync(KEY_PATH)) fail(`${KEY_PATH} already exists — refusing to overwrite`, 2);
  const pair = generateIssuerKeyPair();
  mkdirSync(dirname(KEY_PATH), { recursive: true });
  writeFileSync(KEY_PATH, pair.privateKeyPem, { mode: 0o600 });
  console.log(`private key written to ${KEY_PATH} (gitignored — never commit it)`);
  console.log(`public_key_der_b64: ${pair.publicKeyDerB64}`);
}

function cmdSign(path: string): void {
  if (!existsSync(KEY_PATH)) fail(`no issuer key at ${KEY_PATH} — run keygen first`, 2);
  const unsigned = readJson(path) as Attestation;
  const errors = validateAttestation(unsigned);
  if (errors.length > 0) fail(`invalid attestation:\n  ${errors.join("\n  ")}`, 1);
  const signed = signAttestation(unsigned, readFileSync(KEY_PATH, "utf8"));
  console.log(JSON.stringify(signed, null, 2));
}

function verifyOne(a: Attestation, publicKeys: string[], label: string): boolean {
  const errors = validateAttestation(a);
  if (errors.length > 0) {
    console.error(`${label}: INVALID\n  ${errors.join("\n  ")}`);
    return false;
  }
  const signatureOk = publicKeys.some((k) => verifyAttestationSignature(a, k));
  const validityOk = isWithinValidity(a, new Date());
  console.log(
    `${label}: signature ${signatureOk ? "OK" : "FAILED"}, validity window ${validityOk ? "OK" : "EXPIRED/NOT-YET-VALID"}`,
  );
  return signatureOk && validityOk;
}

function cmdVerify(path: string): void {
  const doc = readJson(path);
  if (isWrapper(doc)) {
    const wrapperErrors = validateWellKnown(doc);
    if (wrapperErrors.length > 0) fail(`invalid wrapper:\n  ${wrapperErrors.join("\n  ")}`, 1);
    const keys = doc.keys.map((k) => k.public_key_der_b64);
    let allOk = true;
    doc.attestations.forEach((a, i) => {
      let ok = verifyOne(a, keys, `attestations[${i}] (level ${a.level}, ${a.witness})`);
      if (a.log_inclusion) {
        const included = verifyMerkleProofFromRootFile(a);
        console.log(`attestations[${i}]: log inclusion ${included ? "OK" : "FAILED"}`);
        ok = ok && included;
      }
      allOk = allOk && ok;
    });
    if (!allOk) process.exit(1);
    return;
  }
  fail("single-attestation verify needs the wrapper for keys — pass the .well-known file", 2);
}

function verifyMerkleProofFromRootFile(a: Attestation): boolean {
  const inclusion = a.log_inclusion;
  if (!inclusion) return false;
  const rootPath = join("kyv", "log", "roots", `${inclusion.date}.json`);
  if (!existsSync(rootPath)) {
    console.error(`kyv: no local root file at ${rootPath} — cannot check inclusion offline`);
    return false;
  }
  const rootDoc = readJson(rootPath) as { root: string };
  return verifyMerkleProof(leafHash(a), inclusion.proof, inclusion.leaf_index, rootDoc.root);
}

function cmdDailyRoot(date: string): void {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) fail("daily-root needs a YYYY-MM-DD date", 2);
  const doc = readJson(WELL_KNOWN_PATH);
  if (!isWrapper(doc)) fail(`${WELL_KNOWN_PATH} is not a kyv wrapper`, 1);
  const leaves = doc.attestations.map((a) => leafHash(a));
  const root = merkleRoot(leaves);
  const rootPath = join("kyv", "log", "roots", `${date}.json`);
  mkdirSync(dirname(rootPath), { recursive: true });
  writeFileSync(
    rootPath,
    `${JSON.stringify({ date, algo: "sha256-merkle-v0", leaf_count: leaves.length, leaves, root }, null, 2)}\n`,
  );
  doc.attestations = doc.attestations.map((a, i) => ({
    ...a,
    log_inclusion: { log: LOG_NAME, date, leaf_index: i, proof: merkleProof(leaves, i) },
  }));
  writeFileSync(WELL_KNOWN_PATH, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`root ${root} over ${leaves.length} leaves → ${rootPath}`);
  console.log(`anchor it: ots stamp ${rootPath}   # then commit ${rootPath} + .ots to kyv-attest/log`);
}

const [command, arg] = process.argv.slice(2);
switch (command) {
  case "keygen":
    cmdKeygen();
    break;
  case "sign":
    if (!arg) fail("sign needs a path to an unsigned attestation JSON", 2);
    cmdSign(arg);
    break;
  case "verify":
    if (!arg) fail("verify needs a path", 2);
    cmdVerify(arg);
    break;
  case "daily-root":
    if (!arg) fail("daily-root needs a YYYY-MM-DD date", 2);
    cmdDailyRoot(arg);
    break;
  default:
    fail("usage: kyv <keygen|sign <file>|verify <file>|daily-root <date>>", 2);
}
