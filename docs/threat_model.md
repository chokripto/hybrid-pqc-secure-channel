# Threat Model

## Attacker Capabilities
- Passive eavesdropping (traffic capture)
- Active network control: modify/inject/drop/replay messages
- “Store now, decrypt later” strategy for long-lived IoT data
- No assumptions about trusted network

## Security Goals
- Confidentiality and integrity of application messages
- PQC-resistant key establishment for long-term confidentiality
- Replay resistance (nonce/counter checks)
- Clear separation of session contexts (session_id binding)

## Out of Scope (v1)
- Physical compromise of endpoints
- Side-channel resistance (timing/power)
- Full PKI lifecycle and certificate management
- Denial-of-Service resilience (rate limiting)

## Main Risks & Mitigations
- MITM during handshake:
  - Not fully mitigated in v1 unless server key is authenticated (future work)
- Replay:
  - mitigated via strict nonce/counter expectations
- Nonce reuse:
  - mitigated via per-session counters + per-direction prefixes
