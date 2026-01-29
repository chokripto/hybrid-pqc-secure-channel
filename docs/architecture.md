
---

## 3) docs/architecture.md
```markdown
# Architecture

## Components
- **Server**: generates hybrid key material and accepts client handshake.
- **Client**: performs Kyber encapsulation + X25519 ECDH, then starts encrypted messaging.
- **Common**:
  - message framing (length-prefixed JSON)
  - HKDF for key derivation
  - AES-GCM for application data

## Key Establishment
### PQC part (Kyber512)
- Server: generates `(pk_pqc, sk_pqc)`
- Client: encapsulates to get `(ct_pqc, ss_pqc)`
- Server: decapsulates `ct_pqc` to recover `ss_pqc`

### Classical part (X25519)
- Server: generates X25519 keypair `(sk_s, pk_s)`
- Client: generates X25519 keypair `(sk_c, pk_c)`
- Shared secret:
  - client: `ss_ecdh = X25519(sk_c, pk_s)`
  - server: `ss_ecdh = X25519(sk_s, pk_c)`

## Hybrid Key Derivation
We mix both secrets:
- `ss_hybrid = ss_pqc || ss_ecdh`
- `K = HKDF(SHA-256, ss_hybrid, salt, info=session_id, length=32)`
This produces an AES-256 key for AES-GCM.

## Secure Channel (AES-GCM)
- Uses unique 12-byte nonce: 4-byte prefix + 8-byte counter
- Separate prefixes per direction to avoid collisions
- AEAD provides confidentiality + integrity

## Deployment
- Docker builds liboqs and installs liboqs-python, ensuring reproducible environment.
