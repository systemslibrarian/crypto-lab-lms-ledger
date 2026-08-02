/**
 * LMS + HSS correctness tests (vitest).
 *
 * These tests would catch the specific problems this repo was raised to fix:
 *   - LM-OTS byte-level correctness vs RFC 8554 Appendix F (rfc8554-vectors.test.ts)
 *   - LMS sign/verify round-trip and forgery-rejection
 *   - The reuse forgery ACTUALLY producing a signature that verifies (hard fail)
 *   - Real two-level HSS: sign, verify, roll-over, and exhaustion
 */

import { describe, it, expect } from 'vitest';
import {
  generateLmsTree,
  lmsSign,
  lmsSignForceReuse,
  lmsVerify,
  forgeFromReuse,
  generateHss,
  hssSign,
  hssVerify,
  H,
  W,
  P,
  otsChainCount,
  signatureSizeBytes,
  rfcLmsSignatureSizeBytes,
  rfcTwoLevelHssSignatureSizeBytes,
} from '../src/lms.ts';

const enc = (s: string) => new TextEncoder().encode(s);
const LEAF_COUNT = 1 << H;

describe('parameter sizing', () => {
  it('p = 67 for w=4 and p = 34 for w=8 (RFC 8554 §4.1)', () => {
    expect(otsChainCount(4)).toBe(67);
    expect(otsChainCount(8)).toBe(34);
    expect(P).toBe(67);
  });

  it('includes the verifier-required randomizer and RFC framing in advertised sizes', () => {
    expect(signatureSizeBytes(4, 5)).toBe(2336);
    expect(rfcLmsSignatureSizeBytes(8, 10)).toBe(1452);
    expect(2 * rfcLmsSignatureSizeBytes(8, 10)).toBe(2904);
    expect(rfcTwoLevelHssSignatureSizeBytes(8, 10)).toBe(2964);
  });
});

describe('LMS sign / verify round-trip', () => {
  it('every signature verifies against the root', async () => {
    let tree = await generateLmsTree({ h: 3 });
    for (let i = 0; i < 4; i++) {
      const msg = enc(`message ${i}`);
      const { signature, updatedTree } = await lmsSign(tree, msg);
      tree = updatedTree;
      expect(await lmsVerify(msg, signature, tree.id, tree.root, tree.w, tree.height)).toBe(true);
    }
  });

  it('rejects a modified message', async () => {
    let tree = await generateLmsTree({ h: 3 });
    const msg = enc('authorized firmware');
    const { signature, updatedTree } = await lmsSign(tree, msg);
    tree = updatedTree;
    const tampered = enc('authorized firmwarX');
    expect(await lmsVerify(tampered, signature, tree.id, tree.root, tree.w, tree.height)).toBe(false);
  });

  it('rejects a modified signature element', async () => {
    let tree = await generateLmsTree({ h: 3 });
    const msg = enc('payload');
    const { signature, updatedTree } = await lmsSign(tree, msg);
    tree = updatedTree;
    const bad = {
      ...signature,
      otsSignature: signature.otsSignature.map((s, i) => {
        if (i !== 0) return s;
        const copy = new Uint8Array(s);
        copy[0] ^= 0xff;
        return copy;
      }),
    };
    expect(await lmsVerify(msg, bad, tree.id, tree.root, tree.w, tree.height)).toBe(false);
  });

  it('rejects a wrong auth path (forged inclusion proof)', async () => {
    let tree = await generateLmsTree({ h: 3 });
    const msg = enc('a');
    const { signature, updatedTree } = await lmsSign(tree, msg);
    tree = updatedTree;
    const bad = {
      ...signature,
      authPath: signature.authPath.map((s, i) => {
        if (i !== 1) return s;
        const copy = new Uint8Array(s);
        copy[0] ^= 0x01;
        return copy;
      }),
    };
    expect(await lmsVerify(msg, bad, tree.id, tree.root, tree.w, tree.height)).toBe(false);
  });

  it('exhausts after 2^h signatures and then throws', async () => {
    let tree = await generateLmsTree({ h: 2 }); // 4 leaves
    for (let i = 0; i < 4; i++) {
      const { updatedTree } = await lmsSign(tree, enc(`x${i}`));
      tree = updatedTree;
    }
    expect(tree.nextIndex).toBe(4);
    await expect(lmsSign(tree, enc('overflow'))).rejects.toThrow(/exhausted/);
  });

  it('single-leaf tree (h=0 edge case) signs and verifies', async () => {
    let tree = await generateLmsTree({ h: 0 }); // 1 leaf, root == leaf
    const msg = enc('only message');
    const { signature, updatedTree } = await lmsSign(tree, msg);
    tree = updatedTree;
    expect(signature.authPath.length).toBe(0);
    expect(await lmsVerify(msg, signature, tree.id, tree.root, tree.w, tree.height)).toBe(true);
    await expect(lmsSign(tree, enc('second'))).rejects.toThrow(/exhausted/);
  });
});

describe('reuse forgery (the attack Section C claims)', () => {
  it('enough reuses of one leaf let an attacker forge a verifying signature', async () => {
    let tree = await generateLmsTree({ h: 3, w: W });
    const leaf = tree.nextIndex;

    // The signer's first (legitimate) signature consumes the leaf...
    const msg0 = enc('Authorized firmware v3.0.0');
    const { signature: sig0, updatedTree } = await lmsSign(tree, msg0);
    tree = updatedTree;
    expect(await lmsVerify(msg0, sig0, tree.id, tree.root, tree.w, tree.height)).toBe(true);

    // ...then reuses it several more times (rollback / clone / restore blunder).
    // ~8 reuses reliably drive the per-position floors low enough to forge at w=4.
    const captures = [{ message: msg0, signature: sig0 }];
    for (let k = 1; k < 8; k++) {
      const m = enc(`Reused signature #${k} — v3.0.${k}`);
      const { signature } = await lmsSignForceReuse(tree, m, leaf);
      expect(await lmsVerify(m, signature, tree.id, tree.root, tree.w, tree.height)).toBe(true);
      captures.push({ message: m, signature });
    }

    const target = enc('Attacker-controlled payload never signed by the owner');
    const { forgedSignature, triesUsed } = await forgeFromReuse(tree, captures, target, leaf);

    // HARD assertion: the forgery must exist and verify under the REAL root.
    expect(forgedSignature, `no randomizer found in ${triesUsed} tries`).not.toBeNull();
    const ok = await lmsVerify(target, forgedSignature!, tree.id, tree.root, tree.w, tree.height);
    expect(ok).toBe(true);
    expect(forgedSignature!.leafIndex).toBe(leaf);
  }, 30000);

  it('never reports a passing forgery that does not actually verify', async () => {
    // A single capture leaves floors high; forging an arbitrary target usually
    // fails. Whatever the outcome, forgeFromReuse must never claim success with
    // a signature that does not verify (the old soft-check bug).
    let tree = await generateLmsTree({ h: 3, w: W });
    const leaf = tree.nextIndex;
    const msg = enc('only one signature revealed');
    const { signature, updatedTree } = await lmsSign(tree, msg);
    tree = updatedTree;

    const target = enc('target that needs a lower digit somewhere');
    const { forgedSignature } = await forgeFromReuse(
      tree, [{ message: msg, signature }], target, leaf, 300,
    );
    if (forgedSignature) {
      const ok = await lmsVerify(target, forgedSignature, tree.id, tree.root, tree.w, tree.height);
      expect(ok).toBe(true);
    } else {
      expect(forgedSignature).toBeNull();
    }
  });
});

describe('HSS — real two-level hierarchy', () => {
  it('signs and verifies across a roll-over, then exhausts', async () => {
    // rootH=2 (4 leaf trees), leafH=1 (2 sigs each) -> capacity 8.
    const { privateKey, publicKey } = await generateHss({ rootH: 2, leafH: 1, w: W });
    let pk = privateKey;
    let rollovers = 0;

    for (let i = 0; i < 8; i++) {
      const msg = enc(`hss #${i}`);
      const { signature, privateKey: next, rolledOver } = await hssSign(pk, msg);
      pk = next;
      if (rolledOver) rollovers++;
      expect(await hssVerify(msg, signature, publicKey)).toBe(true);
    }

    // 4 leaf trees, first activated at keygen, so 3 roll-overs happen during signing.
    expect(rollovers).toBe(3);

    // Capacity 8 reached: next sign must throw (root has no more slots).
    await expect(hssSign(pk, enc('overflow'))).rejects.toThrow(/exhausted/);
  });

  it('HSS verify rejects a tampered message', async () => {
    const { privateKey, publicKey } = await generateHss({ rootH: 1, leafH: 1, w: W });
    const msg = enc('firmware image');
    const { signature } = await hssSign(privateKey, msg);
    expect(await hssVerify(msg, signature, publicKey)).toBe(true);
    expect(await hssVerify(enc('firmware imagX'), signature, publicKey)).toBe(false);
  });

  it('HSS verify rejects a forged leaf public key (wrong root binding)', async () => {
    const { privateKey, publicKey } = await generateHss({ rootH: 1, leafH: 1, w: W });
    const msg = enc('m');
    const { signature } = await hssSign(privateKey, msg);
    const tampered = { ...signature, leafRoot: new Uint8Array(signature.leafRoot) };
    tampered.leafRoot[0] ^= 0xff;
    expect(await hssVerify(msg, tampered, publicKey)).toBe(false);
  });
});

// Guard the demo-visible constants so a future refactor cannot silently change
// the advertised parameter set.
describe('advertised demo parameters', () => {
  it('LMS-SHA256-M32-H5 + LMOTS-SHA256-N32-W4', () => {
    expect(H).toBe(5);
    expect(W).toBe(4);
    expect(LEAF_COUNT).toBe(32);
  });
});
