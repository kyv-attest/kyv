# kyv-attest — Draft Spec Skeleton (v0)

> Status: DRAFT SKELETON — headings, field tables, and enums only; prose lands in W1.
> Naming: "KYV" alone is an established third-party-risk term (the shelf exists), so the spec
> carries a searchable suffix. Candidates considered: `KYV Attestations` / `kyv-attest` / `KYV/1`.
> **Chosen: `kyv-attest`** — a collision-free token that works unchanged as repo name, CLI name,
> spec slug, and search query.

## 1. Abstract

(W1: 1–2 sentences — signed, banded, machine-verifiable operational facts about a company,
published at a well-known URI, verifiable offline, with multiple independent issuers.)

## 2. Terminology

| Term | Meaning |
|---|---|
| subject | The company (identified by domain) the attestation is about |
| issuer | The party signing the attestation (the subject itself, or a third party) |
| witness | How the facts were established: `observed` \| `self` \| `issuer` |
| level | Disclosure tier 0–3 |
| band | A range value (e.g. `">=85"`); raw numbers never appear |
| log | Append-only transparency log with daily Merkle roots |

## 3. Discovery

- Primary: `https://<domain>/.well-known/attestations.json`
- Optional: DNS TXT at `_kyv.<domain>` (key fingerprint + pointer)

## 4. Document format

VC-compatible JSON, Ed25519-signed. Fields:

| Field | Type | Req | Notes |
|---|---|---|---|
| `subject` | string (domain) | ✔ | |
| `issuer` | string (domain or DID) | ✔ | equals `subject` for `witness: self` |
| `witness` | enum | ✔ | `observed` \| `self` \| `issuer` |
| `level` | int 0–3 | ✔ | |
| `alive_since` | date | L1+ | |
| `last_verified` | datetime | L1+ | |
| `continuity` | `{months:int, gaps:int}` | L1+ | a gap = a missed daily log entry |
| `bands` | object | L2+ | band-vocabulary values only |
| `valid_from` / `valid_until` | datetime | ✔ | short TTL; broken sync ⇒ expiry |
| `log_inclusion` | object | ✔ for self/issuer | Merkle inclusion proof |
| `signature` | Ed25519 | ✔ | |

## 5. Levels

| Level | Content | Consent cost |
|---|---|---|
| 0 | domain + public key | one DNS TXT or one file, ~5 min |
| 1 | aliveness + continuity, no financials | near zero |
| 2 | banded financials (e.g. `grr_band: ">=85"`) | bands only, never raw |
| 3 | retention depth (cohort bands) | |

## 6. Witness states

- `observed` — lazy mechanical facts only (domain age, TLS certificate history, HTTP response,
  live checkout present); history backfilled from CT logs + Wayback; DEFAULT state; no judgements.
- `self` — signed by the domain holder; continuity witnessed by the log (a missed day = a gap).
- `issuer` — a third party verified read-only payment data before signing.

## 7. Band vocabulary

Allowed forms: `">=N"`, `"<N"`, `"N-M"` (per-metric enumerations land in W1).
Raw values are non-conforming at every level.

## 8. Validity & revocation

Short TTL; expiry on broken sync; revocation via log entry. (Details W1.)

## 9. Signatures & keys

Ed25519; key publication via `.well-known` + optional DNS TXT; multiple independent issuers
explicitly welcome — the root of trust is the format and the log, not any single key.

## 10. Transparency log

Daily Merkle root → public git repository; inclusion proofs per attestation;
roots anchored via OpenTimestamps.

## 11. Consumer guidance

- `observed` ≠ `attested`; always render provenance.
- **`null` / absent NEVER means negative.** Absence is non-adoption, not a signal.

## 12. Privacy

Bands only. No raw financials, ever, at any level.

## 13. Security considerations

(W1: key rotation, log split-view, replay, domain transfer.)

## 14. Reference implementation

Points to W1 artifacts (`kyv/` in this repo): schema, sign/verify, and Foundr's own first two
attestations (L1 `self`, L2 `issuer` with issuer == subject).
