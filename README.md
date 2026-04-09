[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)
[![Deploy to GitHub Pages](https://github.com/systemslibrarian/crypto-lab-lms-ledger/actions/workflows/pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-lms-ledger/actions/workflows/pages.yml)

# LMS / HSS Ledger

## 1. What It Is

crypto-lab-lms-ledger implements the Leighton-Micali Signature scheme (LMS) and its hierarchical variant (HSS) as specified in NIST SP 800-208 and RFC 8554. LMS is a stateful hash-based signature scheme built on W-OTS+ one-time signatures organized into a Merkle tree. Each leaf in the tree is a W-OTS+ keypair that can be used exactly once — signing with the same leaf twice enables an attacker to forge arbitrary signatures. The state (which leaf to use next) must be maintained persistently and protected against rollback. The security model assumes only the collision resistance of SHA-256 — no number-theoretic hardness assumptions — making LMS post-quantum secure by design.

Implementation: Vite + TypeScript, vanilla CSS, no npm packages. All hashing via `crypto.subtle.digest('SHA-256', ...)`. Parameters: LMS-SHA256-M32-H5 + LMOTS-SHA256-N32-W4 (n=32 bytes, h=5 tree height, w=4 Winternitz, p=67 chain elements).

## 2. When to Use It

- Use LMS/HSS for firmware and software signing when post-quantum security is required and state management is operationally feasible — an HSM with a hardware counter handles state correctly.
- Use HSS with multiple levels when a single LMS tree's capacity (2^h signatures) is insufficient — L=2 with h1=10, h2=10 provides over 1 million signatures.
- Do not use LMS in contexts where state cannot be reliably protected — concurrent signers, backup/restore scenarios, and factory-reset devices all risk catastrophic key reuse.
- Do not use LMS for general-purpose signatures in protocols that require stateless operation — use SPHINCS+ (FIPS 205) instead.
- Do not confuse exhausting the key (using all 2^h leaves) with key compromise — exhaustion is handled gracefully by activating the next HSS tree; reuse is unrecoverable.

## 3. Live Demo

[https://systemslibrarian.github.io/crypto-lab-lms-ledger/](https://systemslibrarian.github.io/crypto-lab-lms-ledger/)

Generate a 32-leaf LMS tree, sign messages one at a time, and watch the key state grid update after each signature. Enable "Force Key Reuse" to see the reuse attack in action — the demo shows real W-OTS+ chain arithmetic revealing private key elements at different chain steps, then constructs and verifies a forged signature for an arbitrary message.

## 4. What Can Go Wrong

- **State rollback:** restoring a backup overwrites `nextIndex` with a smaller value, causing leaf reuse. Hardware counters that cannot be decremented are the correct mitigation.
- **Concurrent signing:** two processes reading the same `nextIndex` simultaneously use the same leaf. State must be updated atomically — database transactions or file locks are required.
- **Tree exhaustion without a successor:** when `nextIndex` reaches `2^h`, the tree is exhausted and new signatures cannot be produced. HSS mitigates this by pre-generating successor trees.
- **Leaf reuse enabling forgery:** a single reuse of any leaf compromises the entire tree — an attacker with two W-OTS+ signatures on the same leaf can forge signatures for arbitrary messages under the same public key.
- **Parameter set confusion:** mixing LMS and LMOTS parameter identifiers produces signatures that appear valid but are computed incorrectly. Always serialize parameter identifiers with signatures per RFC 8554.

## 5. Real-World Usage

- **CNSA 2.0** (NSA, September 2022): designates LMS and XMSS as the required post-quantum signature schemes for software and firmware signing in national security systems, with compliance deadlines from 2025.
- **NIST SP 800-208**: the authoritative standard for LMS and HSS, specifying parameter sets, serialization formats, and state management requirements.
- **UEFI Secure Boot (post-quantum transition)**: LMS is a candidate for next-generation UEFI firmware signing as the industry transitions away from RSA and ECDSA.
- **OpenSSL and Bouncy Castle**: both libraries have implemented LMS/HSS, enabling use in Java and C applications for code signing pipelines.
- **RFC 8554**: the IETF informational RFC documenting the LMS and HSS scheme that NIST SP 800-208 standardizes.

---

**Cross-links:**
- [SPHINCS+ Ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/) — stateless hash-based signatures (FIPS 205)
- [Merkle Vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — Merkle tree construction and inclusion proofs
- [Dilithium Seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA lattice-based signatures (FIPS 204)
- [Falcon Seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/) — NTRU lattice signatures
- [crypto-lab home](https://systemslibrarian.github.io/crypto-lab/)

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
