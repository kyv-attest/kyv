// KYV W2 — procurement pre-flight: a factual counterparty brief for agents
// and humans. Renders the canonical verify JSON as plain sentences with ZERO
// judgement words — facts, provenance, and the absence note; never a score,
// never a recommendation (UNFREEZE-MEMO-KYV §3/§7).
//
// Run: pnpm kyv:preflight <domain>   (or: tsx kyv/preflight.ts <domain>)

import { type AttestationSummary, type VerifyResult, verifyDomain } from "./verify-core";

function attestationLine(a: AttestationSummary): string {
  const parts: string[] = [
    `level ${a.level} attestation, witness "${a.witness}", issuer ${a.issuer}`,
    `signature ${a.signature_valid ? "valid" : "NOT valid"}`,
    a.within_validity ? "within its validity window" : "outside its validity window",
  ];
  if (a.alive_since) parts.push(`alive since ${a.alive_since}`);
  if (a.continuity) {
    parts.push(`continuity ${a.continuity.months} months with ${a.continuity.gaps} gaps`);
  }
  if (a.bands && Object.keys(a.bands).length > 0) {
    const bands = Object.entries(a.bands)
      .map(([metric, band]) => `${metric} ${band}`)
      .join(", ");
    parts.push(`bands: ${bands}`);
  }
  parts.push(a.log_inclusion_present ? "inclusion proof present" : "no inclusion proof");
  return `- ${parts.join("; ")}.`;
}

export function renderBrief(result: VerifyResult): string {
  const lines: string[] = [
    `Counterparty facts for ${result.domain} (checked ${result.checked_at.slice(0, 10)})`,
    "",
    "Attested (kyv-attest):",
  ];
  if (!result.attested.found) {
    lines.push("- No attestation document found. Absence is non-adoption, not a signal.");
  } else if (!result.attested.document_valid) {
    lines.push(
      `- An attestation document exists but does not conform to the convention (${(result.attested.errors ?? []).length} issue(s)); its contents are not rendered.`,
    );
  } else {
    for (const a of result.attested.attestations ?? []) lines.push(attestationLine(a));
  }
  lines.push("", "Observed (mechanical):");
  const o = result.observed;
  if (!o) {
    lines.push("- Observation skipped.");
  } else {
    lines.push(
      `- HTTPS ${o.https_reachable ? `reachable (status ${o.https_status ?? "unknown"})` : "not reached"}.`,
    );
    lines.push(`- First TLS certificate in CT logs: ${o.ct_first_certificate ?? "not determined"}.`);
    lines.push(`- Domain registration (RDAP): ${o.rdap_registered ?? "not determined"}.`);
    lines.push(`- First Wayback capture: ${o.wayback_first_capture ?? "not determined"}.`);
  }
  lines.push("", `Note: ${result.note}`);
  return lines.join("\n");
}

async function main(): Promise<void> {
  const domain = process.argv[2];
  if (!domain) {
    console.error("usage: kyv:preflight <domain>");
    process.exit(2);
  }
  const result = await verifyDomain(domain);
  console.log(renderBrief(result));
}

if (process.argv[1]?.endsWith("preflight.ts")) {
  void main();
}
