# Backend security review: EVM account enrollment verifier

**Scope:** the JSON-RPC quantity parsing correction in `packages/adapters/src/chain/evm-account-enrollment-verifier.ts` and its regression test. This is a focused review, not a full-project security certification.

## Review

| OWASP area | Result | Evidence |
|---|---|---|
| A01 Broken access control | PASS | No route or role changes. Account verification remains organization-scoped and requires a human OWNER/ADMIN in `AccountApplicationService`; backend remains authoritative. |
| A02 Sensitive data / cryptography | PASS | No credentials, secrets, or private keys are read, logged, or returned by the quantity parser. |
| A03 Injection | PASS | RPC messages remain JSON-serialized. A strict canonical hex quantity parser replaces byte-array parsing for only chain ID and block height; no SQL or command construction changed. |
| A04 Insecure design | PASS | Verification remains read-only chain state inspection. The browser does not sign or broadcast; the route activates only after the full account proof succeeds. |
| A05 Security misconfiguration | PASS | Existing RPC URL validation remains unchanged: HTTPS is required except for loopback HTTP; URL userinfo is rejected. |
| A06 Vulnerable components | N/A | No dependencies changed. |
| A07 Authentication failures | PASS | OIDC/JWKS validation and API auth middleware were not modified. |
| A08 Data integrity | PASS | JSON-RPC response IDs and shape continue to be validated; malformed/non-canonical quantity values now fail as `RPC_UNAVAILABLE` rather than being misclassified as an enrollment mismatch. |
| A09 Logging/monitoring | PASS | No new payload logging. Verification errors remain typed and generic at the API boundary. |
| A10 SSRF | PASS | RPC destinations are still selected from startup chain configuration, not user input; the HTTP loopback restriction remains enforced. |

## Validation

The focused regression test demonstrated the previous `0x9` false rejection and now covers a successful proof and malformed `0x09` rejection. The real Anvil/Safe verifier test and authenticated website→API→Anvil click flow passed; see [`VERIFICATION.txt`](./VERIFICATION.txt). No live chain, deployed backend, or external RPC was used.

**Review status:** PASS for the scoped correction. Existing production RPC trust/configuration and full system qualification remain separate gates.
