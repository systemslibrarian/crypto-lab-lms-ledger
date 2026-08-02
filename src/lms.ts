/**
 * LMS + HSS Implementation — NIST SP 800-208 / RFC 8554
 *
 * This is a byte-faithful implementation of the Leighton-Micali Signature
 * scheme and its Hierarchical variant (HSS). The LM-OTS core is validated
 * against RFC 8554 Appendix F Test Case 1 (see test/rfc8554-vectors.test.ts).
 *
 * Demo parameter set:
 *   LMS-SHA256-M32-H5  (n = 32, h = 5 -> 32 leaves per tree)
 *   LMOTS-SHA256-N32-W4 (w = 4, p = 67, ls = 4)
 *
 * The LM-OTS routines are parameterized by w so the exact same code path can
 * be exercised at w = 8 (p = 34, ls = 0) — the parameter set used by RFC 8554's
 * published test vectors — proving byte-level interoperability.
 *
 * All SHA-256 calls go through the Web Crypto API.
 */

// ============================================================
// Byte helpers
// ============================================================

export function concat(...arrays: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

function u8(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff);
}

function u16be(n: number): Uint8Array {
  return Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
}

function u32be(n: number): Uint8Array {
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const compact = hex.replace(/\s+/g, '').toLowerCase();
  const out = new Uint8Array(compact.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(compact.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a[i] ^ b[i];
  return acc === 0;
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const normalized = Uint8Array.from(data);
  const buf = await crypto.subtle.digest('SHA-256', normalized as unknown as ArrayBuffer);
  return new Uint8Array(buf);
}

// ============================================================
// Demo parameters — LMS-SHA256-M32-H5 + LMOTS-SHA256-N32-W4
// ============================================================

export const N = 32;   // hash output length (bytes)
export const H = 5;    // LMS tree height -> 2^5 = 32 leaves
export const W = 4;    // Winternitz parameter for the demo
export const LS = 4;   // checksum left-shift for w = 4

// RFC 8554 Table 1 checksum left-shift ls, keyed by w.
const LS_BY_W: Record<number, number> = { 1: 7, 2: 6, 4: 4, 8: 0 };

export const P = otsChainCount(W); // 67 chain elements per OTS key

/**
 * Number of Winternitz chains p for the n=32 parameter sets, per RFC 8554
 * Section 4.1: p = u + v where u = ceil(8n/w) and v is the number of w-bit
 * digits needed for the checksum. For n=32: w=4 -> p=67, w=8 -> p=34.
 */
export function otsChainCount(w: number): number {
  const u = Math.ceil((8 * N) / w);
  const maxDigit = (1 << w) - 1;
  // RFC 8554 Appendix B: v = ceil((floor(lg((2^w - 1) * u)) + 1) / w).
  // (The ls left-shift only aligns the checksum within these v digits; it does
  // not change how many digits are needed.) w=4 -> v=3; w=8 -> v=2.
  const checksumBits = Math.floor(Math.log2(maxDigit * u)) + 1;
  const v = Math.ceil(checksumBits / w);
  return u + v;
}

// RFC 8554 domain-separation constants (Table 4 / Section 4).
const D_PBLC = 0x8080;
const D_MESG = 0x8181;
const D_LEAF = 0x8282;
const D_INTR = 0x8383;

// ============================================================
// Types
// ============================================================

export interface WotsKey {
  x: Uint8Array[];          // p secret chain-start values, each N bytes
  publicKey: Uint8Array[];  // p chain-end (public) values, each N bytes
  K: Uint8Array;            // OTS public-key hash H(I||q||D_PBLC||y[0..p-1])
  used: boolean;
}

export interface LmsTree {
  id: Uint8Array;           // 16-byte identifier (I in RFC 8554)
  height: number;
  w: number;                // Winternitz parameter used for this tree
  leaves: Uint8Array[];
  nodes: Uint8Array[][];    // nodes[level][index], level 0 = leaves
  root: Uint8Array;
  otsKeys: WotsKey[];
  nextIndex: number;
}

export interface LmsSignature {
  leafIndex: number;
  C: Uint8Array;               // per-signature randomizer (RFC 8554 §4.5)
  otsSignature: Uint8Array[];  // p signature elements
  authPath: Uint8Array[];      // h sibling hashes
}

// ============================================================
// LM-OTS core (parameterized by w) — RFC 8554 Section 4
// ============================================================

/**
 * Winternitz hash chain for OTS digit `i`. Advance `start` from step `from`
 * up to (but not including) `toExclusive`:
 *   tmp_{j+1} = H(I || u32(q) || u16(i) || u8(j) || tmp_j)
 * The chain is one-way: a value at depth d can be advanced to any depth >= d,
 * never reversed. That irreversibility is what makes leaf reuse catastrophic.
 */
export async function chain(
  I: Uint8Array,
  q: number,
  i: number,
  start: Uint8Array,
  from: number,
  toExclusive: number,
): Promise<Uint8Array> {
  let tmp = start;
  const prefix = concat(I, u32be(q), u16be(i));
  for (let j = from; j < toExclusive; j++) {
    tmp = await sha256(concat(prefix, u8(j), tmp));
  }
  return tmp;
}

/** Extract the i-th w-bit coefficient (big-endian) from byte string S. */
export function coef(S: Uint8Array, i: number, w: number): number {
  const bitOffset = i * w;
  const byteIndex = Math.floor(bitOffset / 8);
  const shift = 8 - w - (bitOffset % 8);
  const mask = (1 << w) - 1;
  // w <= 8 always aligns within a single byte for w in {1,2,4,8}.
  return (S[byteIndex] >>> shift) & mask;
}

/** RFC 8554 §4.4 checksum, returned as a 2-byte big-endian value. */
export function checksum(Q: Uint8Array, w: number): Uint8Array {
  const u = Math.ceil((8 * Q.length) / w);
  const maxDigit = (1 << w) - 1;
  let sum = 0;
  for (let i = 0; i < u; i++) sum += maxDigit - coef(Q, i, w);
  const ls = LS_BY_W[w] ?? 0;
  return u16be((sum << ls) & 0xffff);
}

/**
 * The p Winternitz digits signed by an LM-OTS signature: message digest
 * Q = H(I || u32(q) || u16(D_MESG) || C || message) with its checksum appended,
 * split into p coefficients of w bits. Shared by signing, verification, and the
 * reuse-forgery attack so all three agree byte-for-byte.
 */
export async function lmotsCoefficients(
  I: Uint8Array,
  q: number,
  C: Uint8Array,
  message: Uint8Array,
  w: number,
): Promise<number[]> {
  const Q = await sha256(concat(I, u32be(q), u16be(D_MESG), C, message));
  const QwithCksm = concat(Q, checksum(Q, w));
  const p = otsChainCount(w);
  return Array.from({ length: p }, (_, i) => coef(QwithCksm, i, w));
}

/**
 * Recover the candidate LM-OTS public-key hash Kc from a signature. Verification
 * succeeds iff Kc equals the OTS public key committed in the LMS leaf.
 * (RFC 8554 §4.6, Algorithm 4b — the value used in Appendix F.)
 */
export async function lmotsRecoverK(
  I: Uint8Array,
  q: number,
  C: Uint8Array,
  message: Uint8Array,
  otsSignature: Uint8Array[],
  w: number,
): Promise<Uint8Array> {
  const a = await lmotsCoefficients(I, q, C, message, w);
  const maxDigit = (1 << w) - 1;
  const z: Uint8Array[] = [];
  for (let i = 0; i < a.length; i++) {
    z.push(await chain(I, q, i, otsSignature[i], a[i], maxDigit));
  }
  return sha256(concat(I, u32be(q), u16be(D_PBLC), ...z));
}

async function generateWotsKey(I: Uint8Array, q: number, w: number): Promise<WotsKey> {
  const p = otsChainCount(w);
  const maxDigit = (1 << w) - 1;
  const x: Uint8Array[] = [];
  const publicKey: Uint8Array[] = [];
  for (let i = 0; i < p; i++) {
    const start = randomBytes(N);
    x.push(start);
    publicKey.push(await chain(I, q, i, start, 0, maxDigit));
  }
  const K = await sha256(concat(I, u32be(q), u16be(D_PBLC), ...publicKey));
  return { x, publicKey, K, used: false };
}

async function wotsSign(
  I: Uint8Array,
  q: number,
  C: Uint8Array,
  message: Uint8Array,
  key: WotsKey,
  w: number,
): Promise<Uint8Array[]> {
  const a = await lmotsCoefficients(I, q, C, message, w);
  const sig: Uint8Array[] = [];
  for (let i = 0; i < a.length; i++) {
    sig.push(await chain(I, q, i, key.x[i], 0, a[i]));
  }
  return sig;
}

// ============================================================
// LMS Merkle tree — RFC 8554 Section 5
// ============================================================

/** RFC 8554 §5.3 node numbering: leaf q is node 2^h + q; root is node 1. */
function nodeNum(h: number, level: number, index: number): number {
  return (1 << (h - level)) + index;
}

export async function generateLmsTree(
  opts: { h?: number; w?: number; id?: Uint8Array } = {},
): Promise<LmsTree> {
  const h = opts.h ?? H;
  const w = opts.w ?? W;
  const leafCount = 1 << h;
  const id = opts.id ?? randomBytes(16);

  const otsKeys: WotsKey[] = [];
  for (let q = 0; q < leafCount; q++) {
    otsKeys.push(await generateWotsKey(id, q, w));
  }

  const leaves: Uint8Array[] = [];
  for (let q = 0; q < leafCount; q++) {
    const r = nodeNum(h, 0, q);
    leaves.push(await sha256(concat(id, u32be(r), u16be(D_LEAF), otsKeys[q].K)));
  }

  const nodes: Uint8Array[][] = [leaves];
  for (let level = 1; level <= h; level++) {
    const levelNodes: Uint8Array[] = [];
    const count = 1 << (h - level);
    for (let i = 0; i < count; i++) {
      const r = nodeNum(h, level, i);
      levelNodes.push(await sha256(concat(
        id, u32be(r), u16be(D_INTR),
        nodes[level - 1][2 * i],
        nodes[level - 1][2 * i + 1],
      )));
    }
    nodes[level] = levelNodes;
  }

  return { id, height: h, w, leaves, nodes, root: nodes[h][0], otsKeys, nextIndex: 0 };
}

function authPathFor(tree: LmsTree, q: number): Uint8Array[] {
  const authPath: Uint8Array[] = [];
  let nodeIndex = q;
  for (let level = 0; level < tree.height; level++) {
    const siblingIndex = nodeIndex % 2 === 0 ? nodeIndex + 1 : nodeIndex - 1;
    authPath.push(tree.nodes[level][siblingIndex]);
    nodeIndex = Math.floor(nodeIndex / 2);
  }
  return authPath;
}

export async function lmsSign(
  tree: LmsTree,
  message: Uint8Array,
): Promise<{ signature: LmsSignature; updatedTree: LmsTree }> {
  const leafCount = 1 << tree.height;
  if (tree.nextIndex >= leafCount) {
    throw new Error(`LMS tree exhausted: all ${leafCount} one-time keys have been used`);
  }
  const q = tree.nextIndex;
  const C = randomBytes(N);
  const otsSignature = await wotsSign(tree.id, q, C, message, tree.otsKeys[q], tree.w);
  const authPath = authPathFor(tree, q);

  const updatedKeys = tree.otsKeys.map((k, i) => (i === q ? { ...k, used: true } : k));
  const updatedTree: LmsTree = { ...tree, otsKeys: updatedKeys, nextIndex: tree.nextIndex + 1 };

  return { signature: { leafIndex: q, C, otsSignature, authPath }, updatedTree };
}

/** Force-reuse a specific leaf (Section C demonstration only). */
export async function lmsSignForceReuse(
  tree: LmsTree,
  message: Uint8Array,
  leafIndex: number,
): Promise<{ signature: LmsSignature }> {
  const q = leafIndex;
  const C = randomBytes(N);
  const otsSignature = await wotsSign(tree.id, q, C, message, tree.otsKeys[q], tree.w);
  const authPath = authPathFor(tree, q);
  return { signature: { leafIndex: q, C, otsSignature, authPath } };
}

export async function lmsVerify(
  message: Uint8Array,
  signature: LmsSignature,
  id: Uint8Array,
  publicKey: Uint8Array,
  w: number = W,
  h: number = H,
): Promise<boolean> {
  const { leafIndex: q, C, otsSignature, authPath } = signature;
  if (authPath.length !== h) return false;

  const Kc = await lmotsRecoverK(id, q, C, message, otsSignature, w);
  let node = await sha256(concat(id, u32be(nodeNum(h, 0, q)), u16be(D_LEAF), Kc));

  let nodeIndex = q;
  for (let level = 0; level < h; level++) {
    const r = nodeNum(h, level + 1, Math.floor(nodeIndex / 2));
    const sibling = authPath[level];
    node = nodeIndex % 2 === 0
      ? await sha256(concat(id, u32be(r), u16be(D_INTR), node, sibling))
      : await sha256(concat(id, u32be(r), u16be(D_INTR), sibling, node));
    nodeIndex = Math.floor(nodeIndex / 2);
  }
  return bytesEqual(node, publicKey);
}

/** Coefficients (chain depths) for a given (message, C) under leaf q. */
export async function getMsgCoefficients(
  message: Uint8Array,
  id: Uint8Array,
  q: number,
  C: Uint8Array,
  w: number = W,
): Promise<number[]> {
  return lmotsCoefficients(id, q, C, message, w);
}

export function signatureSizeBytes(w: number = W, h: number = H): number {
  return otsChainCount(w) * N + N /* C */ + h * N;
}

/** RFC 8554 serialized LMS signature: q, LM-OTS type, C + y, LMS type, path. */
export function rfcLmsSignatureSizeBytes(w: number = W, h: number = H): number {
  return 12 + signatureSizeBytes(w, h);
}

/** RFC 8554 LMS public key: LMS type, LM-OTS type, 16-byte I, and n-byte root. */
export function rfcLmsPublicKeySizeBytes(): number {
  return 24 + N;
}

/** RFC 8554 two-level HSS signature with identical LMS/LM-OTS parameters. */
export function rfcTwoLevelHssSignatureSizeBytes(w: number = W, h: number = H): number {
  return 4 /* Nspk */ + 2 * rfcLmsSignatureSizeBytes(w, h) + rfcLmsPublicKeySizeBytes();
}

// ============================================================
// Reuse forgery (Section C) — a real LM-OTS grinding attack
// ============================================================

/**
 * A signature captured by the attacker: the message it signed and the full LMS
 * signature (which carries the per-signature randomizer C).
 */
export interface CapturedSignature {
  message: Uint8Array;
  signature: LmsSignature;
}

/**
 * Forge a valid LMS signature on a target message from several genuine
 * signatures that all reused the SAME leaf.
 *
 * This is the real attack, not a shortcut. A Winternitz chain value at depth d
 * can be advanced to any depth >= d but never reversed. Each captured signature
 * reveals, per position i, the chain value at depth a(i). Across k reuses the
 * attacker holds each position's value at the LOWEST depth seen:
 *   floor[i] = min over captures of a(i).
 * The forge step grinds the per-signature randomizer C until every target digit
 * at[i] >= floor[i], then advances each held value forward to at[i]. No secret
 * key material is ever read - only the published signatures. The more the leaf
 * was reused, the lower the floors and the wider the reachable space, which is
 * exactly why reuse is catastrophic (2 reuses of this w=4 set rarely suffice;
 * ~8 reliably forge - see test/lms.test.ts).
 */
export async function forgeFromReuse(
  tree: LmsTree,
  captures: CapturedSignature[],
  targetMessage: Uint8Array,
  leafIndex: number,
  maxTries = 200000,
): Promise<{
  forgedSignature: LmsSignature | null;
  triesUsed: number;
  perSignatureDepths: number[][];
  aTarget: number[];
  reachableFloor: number[];
}> {
  const q = leafIndex;
  const I = tree.id;
  const w = tree.w;
  const p = otsChainCount(w);

  // Distil the captures into per-position minimum depth + the value held there.
  const floor = new Array<number>(p).fill(Number.POSITIVE_INFINITY);
  const floorSig = new Array<Uint8Array>(p);
  const perSignatureDepths: number[][] = [];
  for (const cap of captures) {
    const depths = await lmotsCoefficients(I, q, cap.signature.C, cap.message, w);
    perSignatureDepths.push(depths);
    for (let i = 0; i < p; i++) {
      if (depths[i] < floor[i]) {
        floor[i] = depths[i];
        floorSig[i] = cap.signature.otsSignature[i];
      }
    }
  }

  // Grind the randomizer C until every target coefficient is >= its floor.
  let tries = 0;
  let chosenC: Uint8Array | null = null;
  let aTarget: number[] = [];
  while (tries < maxTries) {
    const C = randomBytes(N);
    const at = await lmotsCoefficients(I, q, C, targetMessage, w);
    tries++;
    let ok = true;
    for (let i = 0; i < p; i++) {
      if (at[i] < floor[i]) { ok = false; break; }
    }
    if (ok) { chosenC = C; aTarget = at; break; }
  }

  if (!chosenC) {
    return {
      forgedSignature: null,
      triesUsed: tries,
      perSignatureDepths,
      aTarget: aTarget.length ? aTarget : new Array(p).fill(0),
      reachableFloor: floor,
    };
  }

  // Advance each held chain value forward from its floor depth to at[i].
  const forgedOts: Uint8Array[] = [];
  for (let i = 0; i < p; i++) {
    forgedOts.push(await chain(I, q, i, floorSig[i], floor[i], aTarget[i]));
  }

  return {
    forgedSignature: {
      leafIndex: q,
      C: chosenC,
      otsSignature: forgedOts,
      authPath: captures[0].signature.authPath,
    },
    triesUsed: tries,
    perSignatureDepths,
    aTarget,
    reachableFloor: floor,
  };
}

// ============================================================
// HSS — Hierarchical Signature System (RFC 8554 Section 6)
// ============================================================

export interface HssPrivateKey {
  L: number;                 // number of levels (2 in this demo)
  rootTree: LmsTree;         // level-0 tree, signs level-1 public keys
  activeLeafTree: LmsTree;   // current level-1 tree, signs messages
  rootSigOfLeaf: LmsSignature; // root's signature over the active leaf's pubkey
  leafH: number;             // height of leaf trees
  leafW: number;
}

export interface HssPublicKey {
  L: number;
  rootId: Uint8Array;
  rootRoot: Uint8Array;      // root LMS public key (the HSS public key)
  rootH: number;
  rootW: number;
}

export interface HssSignature {
  levelUsed: number;         // index of the active leaf tree under the root
  rootSigOfLeaf: LmsSignature;
  leafId: Uint8Array;
  leafRoot: Uint8Array;      // active leaf tree's LMS public key
  leafH: number;
  leafW: number;
  leafSig: LmsSignature;     // signature over the actual message
}

/** Encode a leaf tree's LMS public key as the message the root tree signs. */
function encodeLeafPubKey(levelUsed: number, id: Uint8Array, root: Uint8Array, h: number, w: number): Uint8Array {
  return concat(u32be(levelUsed), id, root, u32be(h), u32be(w));
}

export async function generateHss(
  opts: { rootH?: number; leafH?: number; w?: number } = {},
): Promise<{ privateKey: HssPrivateKey; publicKey: HssPublicKey }> {
  const rootH = opts.rootH ?? 3;
  const leafH = opts.leafH ?? 3;
  const w = opts.w ?? W;

  const rootTree = await generateLmsTree({ h: rootH, w });
  const leafTree = await generateLmsTree({ h: leafH, w });

  const msg = encodeLeafPubKey(0, leafTree.id, leafTree.root, leafH, w);
  const { signature: rootSig, updatedTree: rootAfter } = await lmsSign(rootTree, msg);

  return {
    privateKey: {
      L: 2,
      rootTree: rootAfter,
      activeLeafTree: leafTree,
      rootSigOfLeaf: rootSig,
      leafH,
      leafW: w,
    },
    publicKey: {
      L: 2,
      rootId: rootTree.id,
      rootRoot: rootTree.root,
      rootH,
      rootW: w,
    },
  };
}

/** Total capacity of a two-level HSS = 2^rootH * 2^leafH. */
export function hssCapacity(pk: HssPublicKey, leafH: number): number {
  return (1 << pk.rootH) * (1 << leafH);
}

export interface HssSignResult {
  signature: HssSignature;
  privateKey: HssPrivateKey;
  rolledOver: boolean;
}

/**
 * Sign a message with HSS. When the active leaf tree is exhausted a fresh leaf
 * tree is generated and the root tree signs its public key (a roll-over). This
 * is real signing: the returned signature carries both LMS signatures and
 * verifies end to end.
 */
export async function hssSign(
  privateKey: HssPrivateKey,
  message: Uint8Array,
): Promise<HssSignResult> {
  let pk = privateKey;
  let rolledOver = false;

  const leafLeafCount = 1 << pk.leafH;
  if (pk.activeLeafTree.nextIndex >= leafLeafCount) {
    const rootLeafCount = 1 << pk.rootTree.height;
    if (pk.rootTree.nextIndex >= rootLeafCount) {
      throw new Error('HSS exhausted: root tree has no remaining leaf-tree slots');
    }
    const newLeaf = await generateLmsTree({ h: pk.leafH, w: pk.leafW });
    const levelUsed = pk.rootTree.nextIndex;
    const encoded = encodeLeafPubKey(levelUsed, newLeaf.id, newLeaf.root, pk.leafH, pk.leafW);
    const { signature: rootSig, updatedTree: rootAfter } = await lmsSign(pk.rootTree, encoded);
    pk = { ...pk, rootTree: rootAfter, activeLeafTree: newLeaf, rootSigOfLeaf: rootSig };
    rolledOver = true;
  }

  // levelUsed = index of the leaf tree currently active under the root. It is
  // the root leaf that was consumed to sign the active leaf's public key.
  const levelUsed = pk.rootTree.nextIndex - 1;

  const { signature: leafSig, updatedTree: leafAfter } = await lmsSign(pk.activeLeafTree, message);
  pk = { ...pk, activeLeafTree: leafAfter };

  const signature: HssSignature = {
    levelUsed,
    rootSigOfLeaf: pk.rootSigOfLeaf,
    leafId: pk.activeLeafTree.id,
    leafRoot: pk.activeLeafTree.root,
    leafH: pk.leafH,
    leafW: pk.leafW,
    leafSig,
  };

  return { signature, privateKey: pk, rolledOver };
}

export async function hssVerify(
  message: Uint8Array,
  signature: HssSignature,
  publicKey: HssPublicKey,
): Promise<boolean> {
  if (publicKey.L !== 2) return false;

  // 1. The root tree must have signed the leaf tree's public key.
  const encoded = encodeLeafPubKey(
    signature.levelUsed,
    signature.leafId,
    signature.leafRoot,
    signature.leafH,
    signature.leafW,
  );
  const rootOk = await lmsVerify(
    encoded,
    signature.rootSigOfLeaf,
    publicKey.rootId,
    publicKey.rootRoot,
    publicKey.rootW,
    publicKey.rootH,
  );
  if (!rootOk) return false;

  // 2. The leaf tree must have signed the message.
  return lmsVerify(
    message,
    signature.leafSig,
    signature.leafId,
    signature.leafRoot,
    signature.leafW,
    signature.leafH,
  );
}
