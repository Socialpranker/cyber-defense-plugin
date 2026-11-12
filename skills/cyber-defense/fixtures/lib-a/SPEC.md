# Signed Ticket Format, version 1

A ticket is `base64url(payload) "." hex(mac)`. The payload is a JSON object with
the members `alg`, `sub`, `aud` and `exp`. The MAC is HMAC-SHA256 over the
base64url text with the issuer's key.

## Verifier requirements

1. The verifier MUST reject a ticket whose `alg` is not `HS256`.
2. The verifier MUST compare the MAC in constant time.
3. The verifier MUST reject a ticket whose `exp` is not later than the current time.
4. The verifier MUST reject a ticket whose `aud` differs from the audience the
   verifier was configured with. A ticket issued for one service is not valid at
   another service that shares the issuer's key.
5. The verifier MUST reject a payload that is not a JSON object.
