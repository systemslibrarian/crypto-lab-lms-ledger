import { expect, it } from 'vitest';
import { concat, generateHss, hssSign, hssVerify, lmsVerify } from '../src/lms';

// Independently encode both messages, rather than importing the private encoder
// whose deviation these controls document. RFC 8554 Tables 3/4: H5=5, W4=3.
const u32 = (n: number) => new Uint8Array([n >>> 24, n >>> 16, n >>> 8, n]);

it('the teaching HSS authenticates its custom transcript, not the RFC child key', async () => {
  const { privateKey, publicKey } = await generateHss({ rootH: 5, leafH: 5, w: 4 });
  const message = new TextEncoder().encode('ordinary firmware example');
  const { signature } = await hssSign(privateKey, message);
  const custom = concat(u32(signature.levelUsed), signature.leafId, signature.leafRoot, u32(5), u32(4));
  const rfc = concat(u32(5), u32(3), signature.leafId, signature.leafRoot);
  expect(custom.length).toBe(60);
  expect(rfc.length).toBe(56);
  const verifyRoot = (bytes: Uint8Array) => lmsVerify(bytes, signature.rootSigOfLeaf, publicKey.rootId, publicKey.rootRoot, 4, 5);
  expect(await verifyRoot(custom)).toBe(true);
  expect(await verifyRoot(rfc)).toBe(false);
  expect(await hssVerify(message, signature, publicKey)).toBe(true);
  expect(await hssVerify(new TextEncoder().encode('changed firmware'), signature, publicKey)).toBe(false);
  const changed = new Uint8Array(custom);
  changed[4] ^= 1; // altered child identifier
  expect(await verifyRoot(changed)).toBe(false);
}, 120_000);
