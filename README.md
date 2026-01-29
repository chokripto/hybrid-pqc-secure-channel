# Hybrid Post-Quantum Secure Channel (Kyber512 + X25519)

## Overview
This project implements a **hybrid key establishment** protocol for a secure client/server channel:
- **Kyber512 (PQC KEM)** for post-quantum confidentiality (mitigates “store now, decrypt later”).
- **X25519 (ECDH)** for classical security and interoperability.
- A **hybrid session key** is derived from both secrets using HKDF and used with **AES-GCM (AEAD)**.

This design reflects real-world migration patterns toward PQC, where systems often run **hybrid PQC + classical** during transition.

---

## Security Goals
- Confidentiality and integrity for application data (AEAD).
- Post-quantum resistant key establishment (Kyber).
- Backward-compatible classical security (X25519).
- Replay resistance using per-direction nonces.

---

## Protocol Summary
1. Server sends:
   - Kyber public key `pk_pqc`
   - X25519 public key `pk_ecdh`
   - `session_id`, `salt`, server nonce prefix
2. Client replies:
   - Kyber ciphertext `ct_pqc` and shared secret `ss_pqc`
   - X25519 public key `pk_ecdh_c` and shared secret `ss_ecdh`
3. Both derive:
   - `ss_hybrid = ss_pqc || ss_ecdh`
   - `K = HKDF(ss_hybrid, salt, info=session_id)`
4. Secure channel:
   - AES-GCM with unique nonces per message and per direction.

---

## Repository Docs
- Architecture: `docs/architecture.md`
- Threat Model: `docs/threat_model.md`

---

## How to Run (Docker)
### Build + run (server + client)
```bash
docker-compose up --build
