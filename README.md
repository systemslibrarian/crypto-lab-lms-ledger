# crypto-lab-lms-ledger

## What It Is

crypto-lab-lms-ledger implements the Leighton-Micali Signature scheme (LMS) and its hierarchical variant (HSS) as specified in NIST SP 800-208 and RFC 8554. LMS is a stateful hash-based signature scheme built on LM-OTS (Winternitz) one-time signatures organized into a Merkle tree. Each leaf in the tree is a one-time keypair — reusing a leaf leaks chain values at multiple depths, and after enough reuses an attacker can forge signatures under the same public key. The state (which leaf to use next) must be maintained persistently and protected against rollback. The security model assumes only the second-preimage resistance of SHA-256 (RFC 8554 §9; the per-signature randomizer `C` is what removes the need for full collision resistance) — no number-theoretic hardness assumptions — making LMS post-quantum secure by design.

The LMS/HSS here is a real implementation, not a mock: signing and verification run the RFC 8554 hash-chain, Winternitz checksum, Merkle node numbering, and per-signature randomizer `C`. The LM-OTS core is validated byte-for-byte against **RFC 8554 Appendix F Test Case 1** (`test/rfc8554-vectors.test.ts`), and the HSS demo performs genuine two-level signing with a real root-tree roll-over when a leaf tree fills — every signature is verified end to end.

Implementation: Vite + TypeScript, vanilla CSS, no runtime npm packages (crypto via `crypto.subtle`). Interactive parameters: LMS-SHA256-M32-H5 + LMOTS-SHA256-N32-W4 (n=32 bytes, h=5 tree height, w=4 Winternitz, p=67 chain elements). The interactive HSS demo (Section D) runs a live two-level instance sized h1=3, h2=3 (8 × 8 = 64 signatures) so roll-over and exhaustion are observable in seconds; production deployments size h1/h2 for the device lifetime (see below).

## When to Use It

- Use LMS/HSS for firmware and software signing when post-quantum security is required and state management is operationally feasible — an HSM with a hardware counter handles state correctly.
- Use HSS with multiple levels when a single LMS tree's capacity (2^h signatures) is insufficient — L=2 with h1=10, h2=10 provides over 1 million signatures (the same two-level construction the demo runs at h1=h2=3).
- Do not use LMS in contexts where state cannot be reliably protected — concurrent signers, backup/restore scenarios, and factory-reset devices all risk catastrophic key reuse.
- Do not use LMS for general-purpose signatures in protocols that require stateless operation — use SPHINCS+ (FIPS 205) instead.
- Do not confuse exhausting the key (using all 2^h leaves) with key compromise — exhaustion is handled gracefully by activating the next HSS tree; reuse is unrecoverable.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-lms-ledger](https://systemslibrarian.github.io/crypto-lab-lms-ledger/)**

Generate a 32-leaf LMS tree, sign messages one at a time, and watch the key state grid update after each signature. Enable "Force Key Reuse" to see the reuse attack in action — each reuse leaks another LM-OTS signature and lowers the attacker's reachable "floor" per chain. Once enough signatures have leaked (around eight at this w=4 parameter set), the demo grinds the randomizer `C` and constructs a forged signature for an arbitrary message that verifies against the real tree root. Section D runs a live two-level HSS, signing and verifying real messages and rolling over to a fresh leaf tree when the current one fills.

## What Can Go Wrong

- **State rollback:** restoring a backup overwrites `nextIndex` with a smaller value, causing leaf reuse. Hardware counters that cannot be decremented are the correct mitigation.
- **Concurrent signing:** two processes reading the same `nextIndex` simultaneously use the same leaf. State must be updated atomically — database transactions or file locks are required.
- **Tree exhaustion without a successor:** when `nextIndex` reaches `2^h`, the tree is exhausted and new signatures cannot be produced. HSS mitigates this by pre-generating successor trees.
- **Leaf reuse enabling forgery:** reusing any leaf leaks LM-OTS chain values at multiple depths and compromises the tree. The number of reuses needed to forge an *arbitrary* message depends on the Winternitz parameter (a few reuses at w=8; roughly eight at the demo's w=4); a real deployment must reuse a leaf *zero* times, so a single rollback or clone already breaks the guarantee.
- **Parameter set confusion:** mixing LMS and LMOTS parameter identifiers produces signatures that appear valid but are computed incorrectly. Always serialize parameter identifiers with signatures per RFC 8554.

## Real-World Usage

- **CNSA 2.0** (NSA, September 2022): designates LMS and XMSS as the required post-quantum signature schemes for software and firmware signing in national security systems, with compliance deadlines from 2025.
- **NIST SP 800-208**: the authoritative standard for LMS and HSS, specifying parameter sets, serialization formats, and state management requirements.
- **UEFI Secure Boot (post-quantum transition)**: LMS is a candidate for next-generation UEFI firmware signing as the industry transitions away from RSA and ECDSA.
- **OpenSSL and Bouncy Castle**: both libraries have implemented LMS/HSS, enabling use in Java and C applications for code signing pipelines.
- **RFC 8554**: the IETF informational RFC documenting the LMS and HSS scheme that NIST SP 800-208 standardizes.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-lms-ledger
cd crypto-lab-lms-ledger
npm install
npm run dev
```

## Related Demos

- [crypto-lab-lms-xmss](https://systemslibrarian.github.io/crypto-lab-lms-xmss/) — sibling demo of LMS/HSS with a live index-reuse forgery.
- [crypto-lab-sphincs-ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/) — stateless hash-based signatures (FIPS 205).
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — Merkle tree construction and inclusion proofs.
- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA lattice-based signatures (FIPS 204).
- [crypto-lab-falcon-seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/) — NTRU lattice signatures.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
