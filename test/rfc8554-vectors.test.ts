/**
 * RFC 8554 Appendix F — Known-Answer Test (Test Case 1).
 *
 * This locks the byte-level behaviour of the LM-OTS core: the hash-chain input
 * formatting, the coefficient extraction, the Winternitz checksum, and the
 * public-key-hash. The published vector uses parameter set
 * LMOTS_SHA256_N32_W8 (typecode 0x00000004, w=8, p=34), so we exercise the
 * SAME chain / coefficient / checksum / recovery code the demo uses, at w=8.
 *
 * If the checksum, coefficient split, chain formatting, or public-key hash were
 * wrong (the classic silent bugs in a hand-rolled LM-OTS), the recovered Kc
 * would not match the RFC's published value and this test would fail.
 *
 * Reference: https://www.rfc-editor.org/rfc/rfc8554#appendix-F
 */

import { describe, it, expect } from 'vitest';
import { fromHex, toHex, lmotsRecoverK, otsChainCount, coef, checksum } from '../src/lms.ts';

// RFC 8554 Appendix F, Test Case 1.
const I = fromHex('61a5d57d37f5e46bfb7520806b07a1b8');
const q = 5;
const W8 = 8;

// The message signed in Test Case 1 (US Constitution 10th Amendment text).
const message = fromHex(
  '54686520706f77657273206e6f742064656c65676174656420746f207468652055' +
  '6e6974656420537461746573206279202074686520436f6e737469747574696f6e' +
  '2c206e6f722070726f6869626974656420627920697420746f2074686520537461' +
  '7465732c2061726520726573657276656420746f2074686520537461746573207265' +
  '73706563746976656c792c206f7220746f207468652070656f706c652e0a',
);

// Full LM-OTS signature body from Appendix F (typecode 0x00000004 || C || y[0..33]).
const rfcSigHex = (
  '00000004' +
  'd32b56671d7eb98833c49b433c272586bc4a1c8a8970528ffa04b966f9426eb9' +
  '965a25bfd37f196b9073f3d4a232feb69128ec45146f86292f9dff9610a7bf95' +
  'a64c7f60f6261a62043f86c70324b7707f5b4a8a6e19c114c7be866d488778a0' +
  'e05fd5c6509a6e61d559cf1a77a970de927d60c70d3de31a7fa0100994e162a2' +
  '582e8ff1b10cd99d4e8e413ef469559f7d7ed12c838342f9b9c96b83a4943d16' +
  '81d84b15357ff48ca579f19f5e71f18466f2bbef4bf660c2518eb20de2f66e3b' +
  '14784269d7d876f5d35d3fbfc7039a462c716bb9f6891a7f41ad133e9e1f6d95' +
  '60b960e7777c52f060492f2d7c660e1471e07e72655562035abc9a701b473ecb' +
  'c3943c6b9c4f2405a3cb8bf8a691ca51d3f6ad2f428bab6f3a30f55dd9625563' +
  'f0a75ee390e385e3ae0b906961ecf41ae073a0590c2eb6204f44831c26dd768c' +
  '35b167b28ce8dc988a3748255230cef99ebf14e730632f27414489808afab1d1' +
  'e783ed04516de012498682212b07810579b250365941bcc98142da13609e9768' +
  'aaf65de7620dabec29eb82a17fde35af15ad238c73f81bdb8dec2fc0e7f93270' +
  '1099762b37f43c4a3c20010a3d72e2f606be108d310e639f09ce7286800d9ef8' +
  'a1a40281cc5a7ea98d2adc7c7400c2fe5a101552df4e3cccfd0cbf2ddf5dc677' +
  '9cbbc68fee0c3efe4ec22b83a2caa3e48e0809a0a750b73ccdcf3c79e6580c15' +
  '4f8a58f7f24335eec5c5eb5e0cf01dcf4439424095fceb077f66ded5bec73b27' +
  'c5b9f64a2a9af2f07c05e99e5cf80f00252e39db32f6c19674f190c9fbc506d8' +
  '26857713afd2ca6bb85cd8c107347552f30575a5417816ab4db3f603f2df56fb' +
  'c413e7d0acd8bdd81352b2471fc1bc4f1ef296fea1220403466b1afe78b94f7e' +
  'cf7cc62fb92be14f18c2192384ebceaf8801afdf947f698ce9c6ceb696ed70e9' +
  'e87b0144417e8d7baf25eb5f70f09f016fc925b4db048ab8d8cb2a661ce3b57a' +
  'da67571f5dd546fc22cb1f97e0ebd1a65926b1234fd04f171cf469c76b884cf3' +
  '115cce6f792cc84e36da58960c5f1d760f32c12faef477e94c92eb75625b6a37' +
  '1efc72d60ca5e908b3a7dd69fef0249150e3eebdfed39cbdc3ce9704882a2072' +
  'c75e13527b7a581a556168783dc1e97545e31865ddc46b3c957835da252bb732' +
  '8d3ee2062445dfb85ef8c35f8e1f3371af34023cef626e0af1e0bc017351aae2' +
  'ab8f5c612ead0b729a1d059d02bfe18efa971b7300e882360a93b025ff97e9e0' +
  'eec0f3f3f13039a17f88b0cf808f488431606cb13f9241f40f44e537d302c64a' +
  '4f1f4ab949b9feefadcb71ab50ef27d6d6ca8510f150c85fb525bf25703df720' +
  '9b6066f09c37280d59128d2f0f637c7d7d7fad4ed1c1ea04e628d221e3d8db77' +
  'b7c878c9411cafc5071a34a00f4cf07738912753dfce48f07576f0d4f94f42c6' +
  'd76f7ce973e9367095ba7e9a3649b7f461d9f9ac1332a4d1044c96aefee67676' +
  '401b64457c54d65fef6500c59cdfb69af7b6dddfcb0f086278dd8ad0686078df' +
  'b0f3f79cd893d314168648499898fbc0ced5f95b74e8ff14d735cdea968bee74'
).toLowerCase();

// The candidate LM-OTS public key hash Kc the RFC vector recovers.
const EXPECTED_KC = '8560c5688ade2de58e07a5f729b074e48000d45aeb160f9bc7d01bdb279d3f48';

describe('RFC 8554 Appendix F — LM-OTS known-answer test (w=8)', () => {
  it('p = 34 chains at w = 8', () => {
    expect(otsChainCount(W8)).toBe(34);
  });

  it('recovers the published Kc from the Appendix F signature', async () => {
    const rfcSig = fromHex(rfcSigHex);
    expect(rfcSig.length).toBe(1124); // 4 (type) + 32 (C) + 34*32 (y)

    // Parse: typecode(4) || C(32) || y[0..33](32 each).
    const typecode = (rfcSig[0] << 24) | (rfcSig[1] << 16) | (rfcSig[2] << 8) | rfcSig[3];
    expect(typecode).toBe(0x00000004);

    const C = rfcSig.slice(4, 36);
    const p = otsChainCount(W8);
    const y: Uint8Array[] = [];
    let off = 36;
    for (let i = 0; i < p; i++) {
      y.push(rfcSig.slice(off, off + 32));
      off += 32;
    }

    // Run the SAME recovery path the demo verifier uses, at w=8.
    const Kc = await lmotsRecoverK(I, q, C, message, y, W8);
    expect(toHex(Kc)).toBe(EXPECTED_KC);
  });
});

describe('coefficient extraction and checksum internals', () => {
  it('coef() reads w-bit big-endian digits', () => {
    const S = fromHex('12ab');
    // w=4: 0x1, 0x2, 0xa, 0xb
    expect([0, 1, 2, 3].map((i) => coef(S, i, 4))).toEqual([0x1, 0x2, 0xa, 0xb]);
    // w=8: 0x12, 0xab
    expect([0, 1].map((i) => coef(S, i, 8))).toEqual([0x12, 0xab]);
  });

  it('checksum(all-zero digest) equals u * (2^w - 1) << ls', () => {
    // For w=8, n=32: u=32, maxDigit=255, ls=0 -> 32*255 = 8160 = 0x1FE0.
    const zero = new Uint8Array(32);
    expect(toHex(checksum(zero, 8))).toBe('1fe0');
    // For w=4, n=32: u=64, maxDigit=15, ls=4 -> (64*15)<<4 = 960<<4 = 15360 = 0x3C00.
    expect(toHex(checksum(zero, 4))).toBe('3c00');
  });
});
