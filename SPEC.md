# SPEC: nitro-attest-go

## Goal

Release a data key to a Nitro Enclave only when its attestation document proves (a) AWS hardware signed it, (b) it is fresh and answers our nonce, and (c) the enclave runs the exact code the policy allows.

## Inputs

- `attestation`: the raw document from the enclave's NSM (`/dev/nsm`, `Attestation` request). Bytes, base64 over HTTP.
- `policy`: a JSON file. See [examples/policy.json](examples/policy.json).
- `root`: the AWS Nitro Enclaves root certificate (G1), stored in the repo and pinned by its SHA-256 fingerprint. It is never fetched at runtime.

## Document format

The document is CBOR: a COSE_Sign1 array of four items, sometimes wrapped in CBOR tag 18.

| Index | Item | Check |
|---|---|---|
| 0 | protected header (bstr) | decodes to a map with `alg` (key 1) = -35 (ES384) |
| 1 | unprotected header (map) | ignored |
| 2 | payload (bstr) | the attestation map below |
| 3 | signature (bstr) | 96 bytes, raw r‖s |

Payload map fields:

| Field | Type | Use |
|---|---|---|
| `module_id` | text | logged |
| `digest` | text | must be `"SHA384"` |
| `timestamp` | uint, ms since epoch | freshness |
| `pcrs` | map uint → bstr (48 bytes) | policy match |
| `certificate` | bstr, DER | leaf cert |
| `cabundle` | array of bstr, DER | `[root, …, intermediate]` |
| `public_key` | bstr or null | key wrapping target |
| `user_data` | bstr or null | not used for decisions |
| `nonce` | bstr or null | replay binding |

## Checks, in order

Every check either passes or refuses with a named reason. A refusal stops the request and nothing is released.

1. **decode**: valid CBOR, a COSE_Sign1 shape, every field with the right type. Unknown fields are ignored. Missing required fields are refused.
2. **alg**: the protected header says ES384. Any other value is refused, including `none`.
3. **root_pin**: `cabundle[0]` is the pinned AWS root, byte for byte.
4. **chain**: build `root → cabundle[1..] → certificate` with `crypto/x509`, and verify each link's signature and validity window. The verification time is the service clock, not the document's timestamp.
5. **signature**: build the COSE `Sig_structure` `["Signature1", protected, h'', payload]`, hash it with SHA-384, and verify r‖s against the leaf's P-384 key.
6. **freshness**: `now − timestamp ≤ max_age_secs` and `timestamp − now ≤ max_future_skew_secs`. This runs after the signature check, so only signed timestamps are trusted. (This is the check privacy-rings was missing: [PR #658](https://github.com/helius-labs/privacy-rings/pull/658).)
7. **pcrs**: every PCR listed in the policy is present and equal, compared in constant time. PCRs the policy leaves out are not checked. A policy with no PCRs is refused at load.
8. **nonce**: when `require_nonce` is set, the nonce must equal one the service issued, still unexpired (60 s) and not yet used. It is deleted on first use.
9. **public_key**: when `require_public_key` is set, it must be present and parse as an RSA (≥ 2048) or P-256 key.

## Release

When every check passes, a fresh 32-byte data key is generated and wrapped to `public_key`: RSA-OAEP-SHA-256 for RSA keys, ECIES for P-256. The response is the wrapped key plus the PCR digest that was matched. The plaintext key never leaves the service process unwrapped.

## HTTP

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/v1/nonce` | none | `{ "nonce": base64, "expires_in": 60 }` |
| POST | `/v1/release` | `{ "attestation": base64 }` | 200 `{ "wrapped_key": base64, "pcr_digest": hex }`, or 403 `{ "refused": "<check>", "detail": "…" }` |

## Tests

- One accepting test with a real document captured from a running enclave, checked at a fixed clock.
- One refusing test per check: bad CBOR, `alg` swapped, a foreign root, an expired intermediate, one flipped signature bit, a timestamp at now − 301 s and at now + 301 s, a wrong PCR0, a replayed nonce, a missing public key.
- Boundary tests at exactly 300 s, which are accepted.

## Dependencies

- `github.com/fxamacker/cbor/v2` for CBOR.
- The Go standard library for everything else: `crypto/x509`, `crypto/ecdsa`, `crypto/rsa`, `crypto/subtle`, `net/http`.

## Threats this does not cover

- A compromised AWS root or NSM. That is outside the trust model.
- Side channels inside the enclave.
- A policy that allows the wrong PCRs. The policy file is trusted input.
