/**
 * LMS / HSS Implementation — NIST SP 800-208 / RFC 8554
 *
 * Parameters: LMS-SHA256-M32-H5 + LMOTS-SHA256-N32-W4
 *   n = 32  (SHA-256 output bytes)
 *   h = 5   (tree height, 2^5 = 32 leaf nodes)
 *   w = 4   (Winternitz parameter)
 *   p = 67  (number of OTS chain elements)
 *   ls = 4  (checksum left-shift bits)
 *
 * All SHA-256 calls are async via Web Crypto API.
 */

// ============================================================
// Parameters
// ============================================================

export const N = 32;   // hash output length (bytes)
export const H = 5;    // tree height
export const W = 4;    // Winternitz parameter
export const P = 67;   // chain elements per OTS key
export const LS = 4;   // checksum left-shift
const LEAF_COUNT = 1 << H; // 32

// ============================================================
// Types
// ============================================================

export interface WotsKey {
  privateKey: Uint8Array[]; // p private key elements, each N bytes
  publicKey: Uint8Array[];  // p public key elements, each N bytes
  pkHash: Uint8Array;       // leaf hash = H(id || q || D_PBLC || pk[0]..pk[p-1])
  used: boolean;
}

export interface LmsTree {
  id: Uint8Array;           // 16-byte random identifier (I in RFC 8554)
  height: number;           // h = 5
  leaves: Uint8Array[];     // 2^h leaf hashes
  nodes: Uint8Array[][];    // nodes[level][index], level 0 = leaves
  root: Uint8Array;         // root hash = nodes[h][0]
  otsKeys: WotsKey[];       // 2^h one-time key pairs
  nextIndex: number;        // next unused leaf index (the state)
}

export interface LmsSignature {
  leafIndex: number;
  otsSignature: Uint8Array[];  // p signature elements
  authPath: Uint8Array[];      // h sibling hashes (Merkle proof)
}

// ============================================================
// Crypto utilities
// ============================================================

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data as unknown as ArrayBuffer);
  return new Uint8Array(buf);
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

function u16be(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n & 0xffff, false);
  return b;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

// ============================================================
// RFC 8554 domain-separation constants
// ============================================================

// D_PBLC  = 0x8080  (2-byte, used in OTS public key hash message prefix)
// D_MESG  = 0x8181  (2-byte, used in OTS message hash prefix)
// D_LEAF  = 0x8282  (2-byte, used in Merkle tree leaf node)
// D_INTR  = 0x8383  (2-byte, used in Merkle tree internal node)
// Per RFC 8554 Table 2:
const D_PBLC = new Uint8Array([0x80, 0x80]);
const D_MESG = new Uint8Array([0x81, 0x81]);
const D_LEAF = new Uint8Array([0x82, 0x82]);
const D_INTR = new Uint8Array([0x83, 0x83]);

// ============================================================
// W-OTS+ Chain Function (RFC 8554 Section 3.1)
// ============================================================

/**
 * chain(x, i, s, id, q, chainIndex):
 *   Apply the iterative hash chain starting at step i, for s steps.
 *   Each step: x_j = H(id || u32(q) || u16(chainIndex) || u16(j) || 0xFF || x_{j-1})
 *   where j ranges from i+1 to i+s inclusive.
 */
export async function chain(
  x: Uint8Array,
  i: number,
  s: number,
  id: Uint8Array,
  q: number,
  chainIndex: number
): Promise<Uint8Array> {
  let tmp = x;
  for (let j = i; j < i + s; j++) {
    tmp = await sha256(concat(id, u32be(q), u16be(chainIndex), new Uint8Array([j]), tmp));
  }
  return tmp;
}

// ============================================================
// W-OTS+ Checksum / message formatting (RFC 8554 Section 3.3)
// ============================================================

/**
 * Splits an n-byte hash into p w-bit integers (with checksum).
 * Returns array of length p with values in [0, 2^w - 1].
 */
function coef(S: Uint8Array, i: number, w: number): number {
  // Extract the i-th w-bit block from byte string S
  const bitsPerByte = 8;
  const startBit = i * w;
  const byteIndex = Math.floor(startBit / bitsPerByte);
  const bitOffset = startBit % bitsPerByte;
  // We need up to 2 bytes
  let val = S[byteIndex] << 8;
  if (byteIndex + 1 < S.length) val |= S[byteIndex + 1];
  val = (val >>> (16 - bitOffset - w)) & ((1 << w) - 1);
  return val;
}

/**
 * Compute the message array a[0..p-1] per RFC 8554 Section 3.3:
 *   - First floor(8n/w) elements from message bytes
 *   - Then ls-bit checksum appended as remaining elements
 */
function messageToCoefficients(msgHash: Uint8Array): number[] {
  // Per RFC 8554 with n=32, w=4: u = floor(8*32/4) = 64, p = 67, ls = 4
  const u = Math.floor((8 * N) / W);   // 64
  const a: number[] = [];
  
  // a[0..u-1] from message
  for (let i = 0; i < u; i++) {
    a.push(coef(msgHash, i, W));
  }
  
  // Checksum: sum of (2^w - 1 - a[i]) for i=0..u-1
  const maxw = (1 << W) - 1;
  let csum = 0;
  for (let i = 0; i < u; i++) csum += maxw - a[i];
  
  // Append checksum bits: left-shift by ls bits, then extract in w-bit blocks
  // ls = 4, so we left-shift csum by 4, giving ceil(ls + log2(u*(2^w-1))) / w remaining elements
  // Per RFC 8554: v = ceil((floor(log2(w)) + 1 + floor(log2(u*(2^w-1)))) / w)
  // For w=4, n=32: v = 3 checksum elements, total p = u + v = 64 + 3 = 67
  const csumShifted = csum << LS; // shift left by ls = 4
  
  // Extract 3 w-bit elements from csumShifted (it's a small integer)
  // We treat csumShifted as a big-endian 2-byte value padded to extract
  // The v=3 check elements: indices u, u+1, u+2
  const csumBytes = new Uint8Array(2);
  csumBytes[0] = (csumShifted >> 8) & 0xff;
  csumBytes[1] = csumShifted & 0xff;
  
  const v = P - u; // 3
  for (let i = 0; i < v; i++) {
    a.push(coef(csumBytes, i, W));
  }
  
  return a; // length = P = 67
}

// ============================================================
// W-OTS+ Key Generation (RFC 8554 Section 3.2)
// ============================================================

async function generateWotsKey(id: Uint8Array, q: number): Promise<WotsKey> {
  // 1. Generate p random private key elements
  const privateKey: Uint8Array[] = [];
  for (let i = 0; i < P; i++) {
    privateKey.push(randomBytes(N));
  }
  
  // 2. Compute public key: pk[i] = chain(sk[i], 0, 2^w - 1, id, q, i)
  const maxw = (1 << W) - 1;
  const publicKey: Uint8Array[] = [];
  for (let i = 0; i < P; i++) {
    publicKey.push(await chain(privateKey[i], 0, maxw, id, q, i));
  }
  
  // 3. Compute leaf hash: pkHash = H(id || u32(q) || D_PBLC || pk[0] || ... || pk[p-1])
  const pkHash = await sha256(concat(id, u32be(q), D_PBLC, ...publicKey));
  
  return { privateKey, publicKey, pkHash, used: false };
}

// ============================================================
// W-OTS+ Signing (RFC 8554 Section 3.3)
// ============================================================

async function wotsSign(
  msgHash: Uint8Array,
  key: WotsKey,
  id: Uint8Array,
  q: number
): Promise<Uint8Array[]> {
  const a = messageToCoefficients(msgHash);
  // RFC 8554 Section 3.3: sig[i] = chain(sk[i], 0, a[i]) — value at step a[i]
  const sig: Uint8Array[] = [];
  for (let i = 0; i < P; i++) {
    sig.push(await chain(key.privateKey[i], 0, a[i], id, q, i));
  }
  return sig;
}

// ============================================================
// W-OTS+ Verification: recover public key from signature
// ============================================================

async function wotsRecoverPublicKey(
  msgHash: Uint8Array,
  sig: Uint8Array[],
  id: Uint8Array,
  q: number
): Promise<Uint8Array[]> {
  const a = messageToCoefficients(msgHash);
  const maxw = (1 << W) - 1;
  const pk: Uint8Array[] = [];
  for (let i = 0; i < P; i++) {
    pk.push(await chain(sig[i], a[i], maxw - a[i], id, q, i));
  }
  return pk;
}

// ============================================================
// Merkle tree node index encoding (RFC 8554)
// ============================================================

/**
 * Per RFC 8554 Section 5.3:
 *   For leaf nodes (level 0): r = 2^h + q
 *   For internal nodes: r = (2^(h-level)) + index  ... but the spec
 *   actually numbers nodes 1..2^(h+1)-1 with root=1.
 *   Leaf node q has r = 2^h + q.
 *   Internal node at level lev (0=leaves, h=root), index i has r = 2^(h-lev) + i.
 */
function nodeNum(level: number, index: number): number {
  // level 0 = leaves (bottom), level h = root (top)
  return (1 << (H - level)) + index;
}

// ============================================================
// LMS Tree Construction
// ============================================================

export async function generateLmsTree(): Promise<LmsTree> {
  const id = randomBytes(16);
  
  // Generate all 2^h W-OTS+ keypairs
  const otsKeys: WotsKey[] = [];
  for (let q = 0; q < LEAF_COUNT; q++) {
    otsKeys.push(await generateWotsKey(id, q));
  }
  
  // Leaf hashes = pkHash for each OTS key, wrapped with D_LEAF
  // Per RFC 8554 Section 5.3:
  //   T(r) at leaf: H(I || u32(r) || D_LEAF || OTS_PK_HASH(q))
  // where r = 2^h + q
  const leaves: Uint8Array[] = [];
  for (let q = 0; q < LEAF_COUNT; q++) {
    const r = nodeNum(0, q); // 2^h + q = 32 + q
    const leafNode = await sha256(concat(id, u32be(r), D_LEAF, otsKeys[q].pkHash));
    leaves.push(leafNode);
  }
  
  // Build Merkle tree bottom-up
  // nodes[level][index]: level 0 = leaves, level h = root
  const nodes: Uint8Array[][] = [];
  nodes[0] = leaves;
  
  for (let level = 1; level <= H; level++) {
    const levelNodes: Uint8Array[] = [];
    const nodesAtLevel = 1 << (H - level);
    for (let i = 0; i < nodesAtLevel; i++) {
      const r = nodeNum(level, i);
      // children are nodes[level-1][2i] and nodes[level-1][2i+1]
      const inner = await sha256(concat(
        id, u32be(r), D_INTR,
        nodes[level - 1][2 * i],
        nodes[level - 1][2 * i + 1]
      ));
      levelNodes.push(inner);
    }
    nodes[level] = levelNodes;
  }
  
  const root = nodes[H][0];
  
  return {
    id,
    height: H,
    leaves,
    nodes,
    root,
    otsKeys,
    nextIndex: 0,
  };
}

// ============================================================
// LMS Signing
// ============================================================

export async function lmsSign(
  tree: LmsTree,
  message: Uint8Array
): Promise<{ signature: LmsSignature; updatedTree: LmsTree }> {
  if (tree.nextIndex >= LEAF_COUNT) {
    throw new Error(`LMS tree exhausted: all ${LEAF_COUNT} one-time keys have been used`);
  }
  
  const q = tree.nextIndex;
  
  // Hash the message with domain separator D_MESG
  // Per RFC 8554: msgHash = H(id || u32(q) || D_MESG || message)
  const msgHash = await sha256(concat(tree.id, u32be(q), D_MESG, message));
  
  // Compute W-OTS+ signature
  const otsSignature = await wotsSign(msgHash, tree.otsKeys[q], tree.id, q);
  
  // Collect auth path: sibling nodes at each level on the path from leaf q to root
  const authPath: Uint8Array[] = [];
  let nodeIndex = q;
  for (let level = 0; level < H; level++) {
    const siblingIndex = nodeIndex % 2 === 0 ? nodeIndex + 1 : nodeIndex - 1;
    authPath.push(tree.nodes[level][siblingIndex]);
    nodeIndex = Math.floor(nodeIndex / 2);
  }
  
  // Clone tree and update state
  const updatedKeys = tree.otsKeys.map((k, i) =>
    i === q ? { ...k, used: true } : k
  );
  
  const updatedTree: LmsTree = {
    ...tree,
    otsKeys: updatedKeys,
    nextIndex: tree.nextIndex + 1,
  };
  
  return {
    signature: { leafIndex: q, otsSignature, authPath },
    updatedTree,
  };
}

// ============================================================
// LMS Signing with forced reuse (for Section C demo)
// ============================================================

export async function lmsSignForceReuse(
  tree: LmsTree,
  message: Uint8Array,
  leafIndex: number
): Promise<{ signature: LmsSignature }> {
  const q = leafIndex;
  const msgHash = await sha256(concat(tree.id, u32be(q), D_MESG, message));
  const otsSignature = await wotsSign(msgHash, tree.otsKeys[q], tree.id, q);
  
  const authPath: Uint8Array[] = [];
  let nodeIndex = q;
  for (let level = 0; level < H; level++) {
    const siblingIndex = nodeIndex % 2 === 0 ? nodeIndex + 1 : nodeIndex - 1;
    authPath.push(tree.nodes[level][siblingIndex]);
    nodeIndex = Math.floor(nodeIndex / 2);
  }
  
  return { signature: { leafIndex: q, otsSignature, authPath } };
}

// ============================================================
// LMS Verification
// ============================================================

export async function lmsVerify(
  message: Uint8Array,
  signature: LmsSignature,
  id: Uint8Array,
  publicKey: Uint8Array  // the root hash
): Promise<boolean> {
  const { leafIndex: q, otsSignature, authPath } = signature;
  
  // Recompute message hash
  const msgHash = await sha256(concat(id, u32be(q), D_MESG, message));
  
  // Recover W-OTS+ public key from signature
  const recoveredPk = await wotsRecoverPublicKey(msgHash, otsSignature, id, q);
  
  // Recompute pkHash
  const recoveredPkHash = await sha256(concat(id, u32be(q), D_PBLC, ...recoveredPk));
  
  // Recompute leaf node
  const r0 = nodeNum(0, q);
  let node = await sha256(concat(id, u32be(r0), D_LEAF, recoveredPkHash));
  
  // Walk auth path from leaf to root
  let nodeIndex = q;
  for (let level = 0; level < H; level++) {
    const r = nodeNum(level + 1, Math.floor(nodeIndex / 2));
    const sibling = authPath[level];
    if (nodeIndex % 2 === 0) {
      node = await sha256(concat(id, u32be(r), D_INTR, node, sibling));
    } else {
      node = await sha256(concat(id, u32be(r), D_INTR, sibling, node));
    }
    nodeIndex = Math.floor(nodeIndex / 2);
  }
  
  // Compare recomputed root with publicKey
  if (node.length !== publicKey.length) return false;
  for (let i = 0; i < node.length; i++) {
    if (node[i] !== publicKey[i]) return false;
  }
  return true;
}

// ============================================================
// Forgery demonstration (Section C)
// ============================================================

/**
 * Given two signatures on different messages from the same leaf,
 * demonstrate the forgery attack by constructing a valid signature
 * for a new target message.
 *
 * The attack: for each position i where a2[i] < a1[i],
 * the attacker can extend sig2[i] forward by (a1[i] - a2[i]) steps
 * to recover the private key element at step a1[i].
 *
 * For positions where a_target[i] <= a1[i], they can reconstruct
 * from sig1[i] (going from a1[i] forward to target).
 * For positions where a_target[i] <= a2[i], they can reconstruct
 * from sig2[i].
 *
 * In general: for each i, they can compute sk[i] at step min(a1[i], a2[i])
 * by extending the smaller-step signature, then chain forward to a_target[i].
 */
export async function demonstrateForgery(
  tree: LmsTree,
  sig1: LmsSignature,
  msg1Coefficients: number[],
  sig2: LmsSignature,
  msg2Coefficients: number[],
  targetMessage: Uint8Array,
  leafIndex: number
): Promise<{
  forgedSignature: LmsSignature;
  attackDetails: Array<{ i: number; a1: number; a2: number; aTarget: number; method: string }>;
}> {
  const q = leafIndex;
  const id = tree.id;
  
  const targetMsgHash = await sha256(concat(id, u32be(q), D_MESG, targetMessage));
  const aTarget = messageToCoefficients(targetMsgHash);
  
  const forgedOtsSig: Uint8Array[] = [];
  const attackDetails: Array<{ i: number; a1: number; a2: number; aTarget: number; method: string }> = [];
  
  for (let i = 0; i < P; i++) {
    const a1 = msg1Coefficients[i];
    const a2 = msg2Coefficients[i];
    const at = aTarget[i];
    
    let elem: Uint8Array;
    let method: string;
    
    // RFC 8554 signing: sig[i] = chain(sk[i], 0, a[i]) → value at step a[i]
    // sig1[i] is the chain value at step a1[i], sig2[i] at step a2[i].
    //
    // The attacker can extend either known value forward (cannot go backward).
    // To forge at step a_target[i]:
    //   if at >= a1[i]: extend sig1[i] by (at - a1) steps
    //   elif at >= a2[i]: extend sig2[i] by (at - a2) steps
    //   else: unreachable (need value earlier than any we have)
    
    if (at >= a1) {
      elem = await chain(sig1.otsSignature[i], a1, at - a1, id, q, i);
      method = `extend sig1 (step ${a1} → ${at})`;
    } else if (at >= a2) {
      elem = await chain(sig2.otsSignature[i], a2, at - a2, id, q, i);
      method = `extend sig2 (step ${a2} → ${at})`;
    } else {
      // Can't reach step at — use whichever is closer (forgery will fail at this position)
      const closerStep = a1 <= a2 ? a1 : a2;
      const closerSig = a1 <= a2 ? sig1.otsSignature[i] : sig2.otsSignature[i];
      elem = await chain(closerSig, closerStep, 0, id, q, i);
      method = `unreachable — using step ${closerStep} (forgery may fail at position ${i})`;
    }
    
    forgedOtsSig.push(elem);
    attackDetails.push({ i, a1, a2, aTarget: at, method });
  }
  
  // Auth path is the same (same leaf)
  const authPath = sig1.authPath;
  
  return {
    forgedSignature: { leafIndex: q, otsSignature: forgedOtsSig, authPath },
    attackDetails,
  };
}

/**
 * Compute message coefficients for display/comparison purposes
 */
export async function getMsgCoefficients(
  message: Uint8Array,
  id: Uint8Array,
  q: number
): Promise<number[]> {
  const msgHash = await sha256(concat(id, u32be(q), D_MESG, message));
  return messageToCoefficients(msgHash);
}

/**
 * Signature size in bytes
 */
export function signatureSizeBytes(): number {
  // OTS sig: P × N  + auth path: H × N
  return P * N + H * N;
}
