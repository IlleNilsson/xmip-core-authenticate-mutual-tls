# xmip-core-authenticate-mutual-tls

Authenticate by mutual-tls: the client certificate the TLS handshake proved,
bound to the connection. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

A `mutual-tls` handshake is proven at the transport: the TLS server requested
the client certificate, verified its chain to the anchors it was configured
with, and only then read a byte of content. This gate records what the
transport proved and does not redo the cryptography (ADR-0033). The first
gate (`identify/certificate`) presents the subject with the transport's word
riding as the `mutual-tls.handshake` proof — `verified`, and nothing else
counts. Proven for that; refused, saying so, where the proof is missing or
says anything else, and where the node narrows which issuers it takes and
the reported issuer is not one of them.

## Configuration

`Verifier::new()` takes any client certificate the handshake proved;
`.from_issuer("CN=Partner CA,O=Partner X")` narrows to that issuer, in any
attribute order, and may be called again for another.

## Dependencies

Its capability with the `x509` feature on, for the name an issuer allow-list
compares (ADR-0044), `context` for `Verified` and `xmip-core` for the
mechanism. No key is touched here: the transport's server TLS is where the
chain is verified, and that path is the transport's to grow (ADR-0033 clause
4, steps 2 and 3).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

`cargo test`: four tests — what the handshake verified is proven; a claim
the transport did not vouch for, or vouched for with another word, is
refused saying so; a node that names its issuers takes those and refuses
the rest; another mechanism's claim is refused by name. The included
workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
