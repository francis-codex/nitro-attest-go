# nitro-attest-go

A small Go service that releases a secret to an AWS Nitro Enclave only after it proves what code it is running.

The enclave sends an attestation document. The service checks it, and only if every check passes does it wrap a data key to the public key inside the document. Nothing is released on a partial pass.

**Status: spec stage.** The design and the full list of checks are in [SPEC.md](SPEC.md). Code lands next, check by check, each with a test that feeds it a broken document.

## Why I'm building this

I build Seedless, a non-custodial payout app on Solana. People earn in dollars and get paid out at home in minutes, and the keys that move that money should only ever be handed to code we can prove. While reading the Nitro verifier in Helius's privacy-rings, I found that the attestation document's timestamp was never checked against the clock, so an old signed document kept passing. I sent the fix upstream ([issue #657](https://github.com/helius-labs/privacy-rings/issues/657), [PR #658](https://github.com/helius-labs/privacy-rings/pull/658)). This repo is the same idea, written from scratch in Go: a verifier where every check is explicit and every refusal has a test.

## What it checks

1. The document is a COSE_Sign1 structure, signed with ES384 (ECDSA P-384, SHA-384).
2. The certificate chain runs from the leaf in the document up to a pinned copy of the AWS Nitro root certificate, and each certificate is inside its validity window.
3. The COSE signature verifies against the leaf certificate's public key.
4. The document's timestamp is no more than 300 s old and no more than 300 s in the future.
5. The PCRs (measurements of the enclave image, kernel and app) match the policy exactly.
6. The nonce matches the one the service issued for this request, and is used once.
7. The document carries a public key. The released key is wrapped to it, so only that enclave can open it.

## Planned interface

```
nitro-attest verify doc.cbor --policy examples/policy.json   # prints each check and the verdict
nitro-attest serve --policy examples/policy.json             # HTTP: POST /v1/nonce, POST /v1/release
```

## Out of scope

- Running an enclave. Documents for tests come from fixtures.
- Replacing AWS KMS. KMS already does attestation-gated decrypt. This is the same pattern for keys you hold yourself, with every check visible.

## License

MIT
