/**
 * LMS Ledger — main application entry point
 * Sections: A (explainer), B (live visualizer), C (reuse attack), D (HSS), E (deployment)
 */

import './style.css';
import {
  generateLmsTree,
  lmsSign,
  lmsSignForceReuse,
  lmsVerify,
  forgeFromReuse,
  getMsgCoefficients,
  generateHss,
  hssSign,
  hssVerify,
  toHex,
  H,
  P,
  N,
  W,
} from './lms';
import type { LmsTree, LmsSignature, HssPrivateKey, HssPublicKey } from './lms';

// App state
let tree: LmsTree | null = null;
let lastSignature: LmsSignature | null = null;
let lastMessage: Uint8Array | null = null;

// Reuse attack state — the attacker collects several signatures on ONE leaf.
interface Capture { message: Uint8Array; signature: LmsSignature; coefs: number[] }
let reuseEnabled = false;
let reuseLeafIndex = 0;
let reuseCaptures: Capture[] = [];
let reuseDetected = false;
let signingLocked = false;

const LEAF_COUNT = 1 << H;
const WOTS_STEPS = 1 << W; // 16 hash-chain steps (0..15); step 15 is the public key
const CHAINS_SHOWN = 8;    // how many of the p=67 chains to visualize at once

// HSS interactive demo state (Section D) — a REAL two-level HSS instance.
// Root tree h1=3 (8 leaf-tree slots), leaf trees h2=3 (8 signatures each) ->
// 8 x 8 = 64 total signatures. Every "Sign" here performs genuine LMS signing
// on the active leaf tree; a full leaf tree triggers a real root-tree roll-over.
const HSS_ROOT_H = 3;
const HSS_LEAF_H = 3;
const HSS_L1 = 1 << HSS_ROOT_H; // 8
const HSS_L2 = 1 << HSS_LEAF_H; // 8
const HSS_CAP = HSS_L1 * HSS_L2; // 64
let hssPriv: HssPrivateKey | null = null;
let hssPub: HssPublicKey | null = null;
let hssTotalUsed = 0;
let hssLastVerified = false;
let hssBusy = false;

// ============================================================
// LM-OTS hash-chain visualizer (teaching device)
// Each chain is 2^w = 16 nodes: step 0 = sk (secret), step 15 = pk (public).
// A signature reveals the chain value at step a[i]; the verifier re-derives
// everything from there up to pk. Reuse reveals a second, lower depth.
// ============================================================

interface ChainRowSpec {
  i: number;       // chain position (0..p-1)
  a1: number;      // first revealed depth
  a2?: number;     // second revealed depth (reuse mode)
  target?: number; // forged-target depth
}

function renderChainDiagram(rows: ChainRowSpec[], mode: 'sign' | 'reuse'): string {
  const body = rows.map(({ i, a1, a2, target }) => {
    const lo = a2 === undefined ? a1 : Math.min(a1, a2);
    const nodes = Array.from({ length: WOTS_STEPS }, (_, step) => {
      const cls = ['chain-node'];
      if (step === 0) cls.push('sk');
      if (step === WOTS_STEPS - 1) cls.push('pk');
      if (mode === 'sign') {
        if (step < a1) cls.push('secret');
        else if (step > a1) cls.push('derivable');
        if (step === a1) cls.push('revealed');
      } else {
        if (step >= lo) cls.push('forgeable');
        if (step === a1) cls.push('reveal-a');
        if (a2 !== undefined && step === a2) cls.push('reveal-b');
        if (target !== undefined && step === target) {
          cls.push('target', target >= lo ? 'reachable' : 'unreachable');
        }
      }
      const note = step === 0 ? ' = sk (secret)' : step === WOTS_STEPS - 1 ? ' = pk (public)' : '';
      return `<span class="${cls.join(' ')}" title="step ${step}${note}"></span>`;
    }).join('');
    const meta = mode === 'sign'
      ? `a=${a1}`
      : `a1=${a1}, a2=${a2}${target !== undefined ? `, t=${target}` : ''}`;
    return `<div class="chain-row">
      <span class="chain-row-label">pos ${i}</span>
      <div class="chain-track" role="img" aria-label="Chain for position ${i}: ${meta}">${nodes}</div>
      <span class="chain-row-meta">${meta}</span>
    </div>`;
  }).join('');
  return `<div class="chain-diagram">${body}</div>`;
}

// Show the first CHAINS_SHOWN chains inline; tuck the rest behind a native
// <details> disclosure so the default view stays legible on mobile.
function renderChainsCollapsible(rows: ChainRowSpec[], mode: 'sign' | 'reuse'): string {
  const head = rows.slice(0, CHAINS_SHOWN);
  const rest = rows.slice(CHAINS_SHOWN);
  let html = renderChainDiagram(head, mode);
  if (rest.length) {
    html += `<details class="chain-more">
      <summary>Show all ${rows.length} chains <span class="chain-more-count">(+${rest.length})</span></summary>
      ${renderChainDiagram(rest, mode)}
    </details>`;
  }
  return html;
}

function chainLegend(mode: 'sign' | 'reuse'): string {
  const items = mode === 'sign'
    ? [
        ['sk', 'sk · step 0 (secret)'],
        ['revealed', 'revealed signature'],
        ['secret', 'stays secret'],
        ['derivable', 'verifier re-derives'],
        ['pk', 'pk · step 15 (public)'],
      ]
    : [
        ['reveal-a', 'depth from msg A'],
        ['reveal-b', 'depth from msg B'],
        ['forgeable', 'forgeable region (≥ min)'],
        ['target reachable', 'target — forgeable'],
        ['target unreachable', 'target — blocked'],
      ];
  return `<div class="chain-legend">${items
    .map(([c, label]) => `<span><i class="chain-swatch ${c}"></i>${label}</span>`)
    .join('')}</div>`;
}


// ============================================================
// HTML template
// ============================================================

function renderApp(): string {
  const keyCells = Array.from({ length: LEAF_COUNT }, (_, i) =>
    `<div class="key-cell" id="key-cell-${i}" data-index="${i}" role="img" aria-label="Key ${i}: available">${i}</div>`
  ).join('');

  return `
<div id="init-overlay" role="status" aria-live="polite">
  <span class="spinner" aria-hidden="true"></span>
  <span>Generating LMS tree (32 LM-OTS keypairs)\u2026</span>
</div>

<a class="skip-link" href="#section-a">Skip to content</a>

<nav class="site-nav" aria-label="Section navigation">
  <div class="container">
    <a href="#section-a">A &middot; What is LMS?</a>
    <a href="#section-b">B &middot; Key State Visualizer</a>
    <a href="#section-c">C &middot; Reuse Attack</a>
    <a href="#section-d">D &middot; HSS Hierarchy</a>
    <a href="#section-e">E &middot; Deployment</a>
  </div>
</nav>

<main>
<div class="container">

<header class="cl-hero">
  <div class="cl-hero-main">
    <h1 class="cl-hero-title">LMS Ledger</h1>
    <p class="cl-hero-sub">LMS/HSS &middot; NIST SP 800-208 &middot; RFC 8554</p>
    <p class="cl-hero-desc">Build an LMS Merkle tree of one-time LM-OTS keys and sign message by message, watching the nextIndex state advance so each leaf is spent exactly once.</p>
  </div>
  <aside class="cl-hero-why" aria-label="Why it matters">
    <span class="cl-hero-why-label">WHY IT MATTERS</span>
    <p class="cl-hero-why-text">Stateful hash-based signatures resist quantum attacks, but their security hinges on never reusing a leaf. Lose the state and reuse one key, and an attacker recovers hidden hash-chain values to forge signatures on messages you never signed.</p>
  </aside>
  <button class="theme-toggle" id="theme-toggle" aria-label="Switch to light theme">🌙</button>
</header>

<section class="section" id="section-a">
  <div class="section-header">
    <span class="section-tag">A</span>
    <h2>What is a stateful hash-based signature?</h2>
  </div>
  <div class="card">
    <h3>A1 &mdash; Hash-based signatures from one-time keys</h3>
    <p>The conceptual foundation is the <strong>Lamport one-time signature</strong>. To sign a 1-bit message <em>b</em>: publish <code>H(sk_b)</code> as the public key. The signature is <code>sk_b</code> &mdash; the verifier checks <code>H(sk_b)</code> matches the published value. The key can only be used once: revealing <code>sk_0</code> to sign a <code>0</code> makes it impossible to later sign a <code>1</code> securely.</p>
    <p><strong>LM-OTS</strong> (the Winternitz one-time signature of RFC 8554 &sect;4 &mdash; a relative of, but not the same scheme as, XMSS/SLH-DSA's WOTS+) generalizes this using hash chains. Per the RFC &sect;4.5 signature-generation algorithm: <code>sig[i] = chain(sk[i], 0, a[i])</code> where <code>a[i]</code> is the <em>i</em>-th <em>w</em>-bit coefficient of the message hash. Verification completes the chain: <code>chain(sig[i], a[i], 2^w&minus;1&minus;a[i])</code> must recover <code>pk[i]</code>.</p>
    <div class="chain-primer">
      <p class="chain-primer-caption">A hash chain is a one-way street. Repeatedly hashing turns a secret <code>sk</code> into a public <code>pk</code> over 2<sup>w</sup>=16 steps. You can always walk <em>forward</em> (hash again), but never <em>backward</em>. Signing publishes one node partway along (here, step&nbsp;9); the verifier hashes it forward to <code>pk</code>, while everything below stays secret:</p>
      ${renderChainDiagram([{ i: 0, a1: 9 }], 'sign')}
      ${chainLegend('sign')}
    </div>
    <p><strong>LMS</strong> organizes 2^h LM-OTS keypairs into a Merkle tree. The root is the LMS public key. An LMS signature includes the OTS signature for the chosen leaf plus an auth path (h sibling hashes) to reconstruct the root. Each leaf is used exactly once.</p>
    <div class="info-box"><strong>Parameters in this demo:</strong> LMS-SHA256-M32-H5 + LMOTS-SHA256-N32-W4 per NIST SP 800-208 &mdash; 32 bytes (SHA-256), tree height h=5, Winternitz w=4, p=67 chain elements per OTS key. The tree supports <strong>32 one-time signatures</strong>.</div>
  </div>
  <div class="card">
    <h3>A2 &mdash; The state requirement</h3>
    <p>LMS requires tracking which leaves have been used. The state is a single integer: <code>nextIndex</code>. This counter must be:</p>
    <ul style="margin:0.5rem 0 0.85rem 1.5rem;line-height:2;">
      <li><strong>Persisted across reboots</strong> &mdash; stored in non-volatile memory or a secure counter</li>
      <li><strong>Synchronized across signing instances</strong> &mdash; no two signers can use the same leaf</li>
      <li><strong>Monotonically increasing</strong> &mdash; rollback to a previous index is catastrophic</li>
    </ul>
    <p>An HSM or TPM with a hardware counter is the typical deployment. Software-only implementations must protect the state file from corruption, rollback, and concurrent writes using atomic operations or database transactions.</p>
    <div class="warn-box"><strong>\u26a0 State is the entire security contract.</strong> A state rollback that replays <code>nextIndex</code> has the same effect as intentional key reuse &mdash; see Section C for a live demonstration.</div>
  </div>
  <div class="card">
    <h3>A3 &mdash; Why stateful schemes exist</h3>
    <p>Stateless schemes like SPHINCS+ (FIPS 205) avoid state but pay in signature size (~8 KB for SPHINCS+-SHA-256-128s). LMS signature size depends on the Winternitz parameter <em>w</em>, so it is only meaningful once <em>w</em> is named: at h=10 an RFC 8554 signature is <strong>1,452 bytes</strong> with LMOTS-SHA256-N32-W8 (p=34), and <strong>2,508 bytes</strong> with the W4 set (p=67) this demo signs with. Against SPHINCS+-128s that is roughly 5&times; smaller at w=8 and 3&times; smaller at w=4 &mdash; decisive when signatures must fit in firmware manifest headers or be transmitted over constrained IoT channels. Verification requires only hash operations (no field arithmetic).</p>
    <div class="table-wrap">
      <table>
        <caption class="sr-only">Comparison of LMS, SPHINCS+, and Ed25519 signature schemes</caption>
        <thead><tr><th scope="col">Property</th><th scope="col">LMS (h=10, w=8)</th><th scope="col">SPHINCS+-128s</th><th scope="col">Ed25519</th></tr></thead>
        <tbody>
          <tr><td>Public key</td><td>56 bytes</td><td>32 bytes</td><td>32 bytes</td></tr>
          <tr><td>Signature</td><td>1,452 B (2,508 B at w=4)</td><td>7,856 B</td><td>64 bytes</td></tr>
          <tr><td>Signing speed</td><td>Fast</td><td>Slow</td><td>Very fast</td></tr>
          <tr><td>Verification speed</td><td>Fast</td><td>Fast</td><td>Very fast</td></tr>
          <tr><td>State required</td><td><span class="text-warning">Yes</span></td><td><span class="text-accent">No</span></td><td><span class="text-accent">No</span></td></tr>
          <tr><td>Post-quantum</td><td><span class="text-accent">Yes</span></td><td><span class="text-accent">Yes</span></td><td><span class="text-danger">No</span></td></tr>
          <tr><td>Standard</td><td>SP 800-208</td><td>FIPS 205</td><td>RFC 8032</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<section class="section" id="section-b">
  <div class="section-header">
    <span class="section-tag interactive">B &middot; Interactive</span>
    <h2>Live LMS Key State Visualizer</h2>
  </div>
  <div class="guide-banner" role="note">
    <strong>How to drive this demo:</strong>
    <span class="guide-step"><span class="guide-num">1</span> Sign a message &mdash; watch a leaf flip to <em>used</em> and see how the signature is built</span>
    <span class="guide-step"><span class="guide-num">2</span> Verify it against the root (the public key)</span>
    <span class="guide-step"><span class="guide-num">3</span> In <a href="#section-c">Section&nbsp;C</a>, reuse one leaf and forge a signature</span>
  </div>
  <div class="card">
    <h3>Key State &mdash; LMS-SHA256-M32-H5 (32-leaf tree)</h3>
    <div class="state-counter-display" id="state-counter">
      <span class="state-counter-label">State:</span>
      <span class="state-counter-value" id="counter-value">nextIndex = 0</span>
      <span class="state-remaining" id="counter-remaining">32 signatures remaining</span>
    </div>
    <div class="key-grid" id="key-grid" role="group" aria-label="LMS key state grid — 32 one-time keys">${keyCells}</div>
    <div class="flex-row" style="gap:0.5rem;flex-wrap:wrap;font-size:0.75rem;">
      <span style="color:var(--key-available-text)">&#9632; Available</span>
      <span style="color:var(--key-used-text)">&#9632; Used</span>
      <span style="color:var(--key-exhausted-text)">&#9632; Exhausted</span>
      <span style="color:var(--key-reused-text)">&#9632; Reused (danger)</span>
    </div>
  </div>
  <div class="signing-layout">
    <div class="card" id="signing-panel">
      <h3>Sign Message</h3>
      <div class="form-group">
        <label for="sign-message">Message</label>
        <textarea id="sign-message" rows="3">Firmware v2.4.1 &mdash; SHA-256: a3f8c1d9e0b2...</textarea>
      </div>
      <div class="flex-row">
        <button class="btn btn-primary" id="btn-sign">&#9997; Sign Message</button>
        <button class="btn btn-secondary" id="btn-reset-tree">&#8635; Reset Tree</button>
      </div>
      <div id="sign-result" class="hidden mt-2" aria-live="polite">
        <hr class="divider">
        <div id="sign-walkthrough" class="walkthrough"></div>
        <div class="result-panel" id="sign-result-content"></div>
      </div>
      <div id="exhausted-msg" class="hidden warn-box mt-2">
        &#128274; Tree exhausted &mdash; all 32 one-time keys have been used. Click "Reset Tree" to generate a new keypair.
      </div>
    </div>
    <div class="card">
      <h3>Verify Signature</h3>
      <div class="form-group">
        <label for="verify-message">Message</label>
        <textarea id="verify-message" rows="3" placeholder="Sign a message first\u2026" readonly></textarea>
      </div>
      <div class="form-group">
        <label for="verify-sig-display">Signature (hex, first element)</label>
        <textarea id="verify-sig-display" rows="3" readonly placeholder="Signature will appear here\u2026"></textarea>
      </div>
      <button class="btn btn-primary" id="btn-verify" disabled>&#10003; Verify</button>
      <div id="verify-result" class="hidden mt-2" aria-live="polite">
        <hr class="divider">
        <div id="verify-result-content"></div>
      </div>
    </div>
  </div>
  <div class="card hidden" id="auth-path-card">
    <h3>Auth Path (Merkle proof)</h3>
    <p class="text-muted" style="font-size:0.82rem;margin-bottom:0.75rem;">The h=5 sibling hashes needed to reconstruct the root from leaf q.</p>
    <div id="auth-path-display" class="auth-path-display"></div>
  </div>
</section>

<section class="section" id="section-c">
  <div class="section-header">
    <span class="section-tag danger">C &middot; Attack Demo</span>
    <h2>The One-Time Key Reuse Attack</h2>
  </div>
  <div class="card">
    <h3>C1 &mdash; What happens when you reuse a leaf</h3>
    <p>LM-OTS security depends on the signer never revealing more than one signature per leaf. Per RFC 8554 &sect;4.5: <code>sig[i] = chain(x[i], 0, a[i])</code> &mdash; the signature element at position <em>i</em> is the chain value at step <code>a[i]</code>, where <code>a</code> depends on the message and a per-signature randomizer <code>C</code>.</p>
    <p>Each reuse of leaf <code>q</code> leaks another set of chain values. Because a chain value can be advanced <em>forward</em> but never reversed, after <em>k</em> reuses the attacker holds each position at its <strong>lowest</strong> revealed depth <code>floor[i] = min</code> over the <em>k</em> signatures. To forge a chosen message the attacker grinds the randomizer <code>C</code> until every target digit <code>at[i] &ge; floor[i]</code>, then advances each held value forward to <code>at[i]</code>.</p>
    <div class="danger-box"><strong>&#128308; Reuse compromises the whole tree.</strong> With this teaching parameter set (w=4, 67 chains) two reuses rarely suffice, but the floors drop fast: around <strong>eight</strong> reuses make forging an arbitrary message reliable, and every extra reuse makes it easier. A real deployment reuses a leaf zero times &mdash; one rollback or clone is already a standing invitation.</div>
  </div>
  <div class="card">
    <h3>C2 &mdash; Live reuse demonstration</h3>
    <div class="toggle-row">
      <label class="toggle" for="reuse-toggle"><input type="checkbox" id="reuse-toggle" aria-label="Force key reuse (demonstration only)" aria-describedby="reuse-toggle-label"><span class="toggle-slider" aria-hidden="true"></span></label>
      <span class="toggle-label" id="reuse-toggle-label">Force Key Reuse (disabled)</span>
    </div>
    <div id="reuse-sign-area">
      <div class="form-group">
        <label for="reuse-msg-a">First message (consumes leaf q legitimately)</label>
        <textarea id="reuse-msg-a" rows="2">Firmware v3.0.0 &mdash; authorized release</textarea>
      </div>
      <div class="flex-row">
        <button class="btn btn-primary" id="btn-sign-a">Sign (consume leaf q)</button>
        <button class="btn btn-primary" id="btn-sign-b" disabled>&#8635; Reuse leaf q (+1 leaked signature)</button>
      </div>
      <p class="text-muted" style="font-size:0.8rem;margin-top:0.5rem;" id="reuse-count-note">Enable "Force Key Reuse", then reuse the leaf several times &mdash; each click leaks another signature and lowers the attacker's floor.</p>
    </div>
    <div id="reuse-warning" class="warning-banner hidden" role="alert">&#9888; REUSE DETECTED &mdash; Multiple signatures from the same one-time key. The key is now compromised.</div>
    <div id="locked-msg" class="locked-msg hidden" role="alert">&#128308; KEY COMPROMISED &mdash; Generate a new tree (Reset Tree in Section B) to continue normal signing.</div>
    <div id="reuse-results" class="hidden">
      <hr class="divider">
      <div class="sig-compare" id="sig-compare-display"></div>
      <p class="text-muted mt-1" style="font-size:0.8rem;" id="reuse-explanation"></p>
    </div>
  </div>
  <div class="card" id="forgery-card">
    <h3>C3 &mdash; Forgery demonstration</h3>
    <p style="font-size:0.86rem;" class="text-muted" id="forgery-prereq-msg">Reuse the leaf at least twice above (the more the better) to unlock the forgery demo.</p>
    <div id="forgery-area" class="hidden">
      <div class="form-group">
        <label for="forgery-target-msg">Target message (not previously signed)</label>
        <textarea id="forgery-target-msg" rows="2">Firmware v4.0.0 &mdash; attacker-controlled payload</textarea>
      </div>
      <button class="btn btn-danger" id="btn-forge">&#128275; Demonstrate Forgery</button>
      <div id="forgery-result" class="hidden mt-2" aria-live="polite"><div id="forgery-result-content"></div></div>
    </div>
  </div>
  <div class="card">
    <h3>C4 &mdash; Why hardware counters matter</h3>
    <p>The reuse attack is not theoretical &mdash; it has occurred in practice when:</p>
    <ul style="margin:0.5rem 0 0.85rem 1.5rem;line-height:2;font-size:0.88rem;">
      <li>A signing device is reset to a factory state (state rollback)</li>
      <li>A backup restore overwrites the state file with an older version</li>
      <li>Two servers are cloned from the same image and sign concurrently</li>
    </ul>
    <p>NIST SP 800-208 &sect;9.1 (Security Considerations &mdash; One-Time Signature Key Reuse) states that extreme care is needed to avoid accidental OTS key reuse: the private key's state must be updated each time a signature is generated, and where the key lives in non-volatile memory that update must be committed to mark the OTS key unavailable <em>before</em> the signature generated with it is exported. The normative conformance requirements sit in &sect;8.1. On hardware, SP 800-208 notes that some cryptographic modules implement monotonic counters and that using one to choose the OTS key may be very helpful in avoiding unintentional reuse. The TPM 2.0 specification provides NV counters of this kind &mdash; they only increment, so a counter-backed index cannot be rolled back in place.</p>
  </div>
</section>

<section class="section" id="section-d">
  <div class="section-header">
    <span class="section-tag">D</span>
    <h2>HSS &mdash; Hierarchical Signature System</h2>
  </div>
  <div class="card">
    <h3>D1 &mdash; Scaling beyond 2^h signatures</h3>
    <p>A single LMS tree with h=5 supports only 32 signatures. For deployment:</p>
    <div class="table-wrap">
      <table>
        <caption class="sr-only">LMS tree heights and signature capacities</caption>
        <thead><tr><th scope="col">Height h</th><th scope="col">Signatures</th><th scope="col">Use case</th></tr></thead>
        <tbody>
          <tr><td>h = 5</td><td>32</td><td>Demo / testing</td></tr>
          <tr><td>h = 10</td><td>1,024</td><td>Certificate authority, infrequent signing</td></tr>
          <tr><td>h = 20</td><td>1,048,576 (~1M)</td><td>Firmware signing (device lifetime)</td></tr>
          <tr><td>h = 25</td><td>~33 million</td><td>High-volume code signing</td></tr>
        </tbody>
      </table>
    </div>
    <p>The challenge: generating all 2^h LM-OTS keypairs upfront (for h=20: 1 million computations). HSS solves this with a multi-level tree hierarchy so only the current leaf tree needs to be precomputed.</p>
  </div>
  <div class="card">
    <h3>D2 &mdash; HSS structure (NIST SP 800-208 &sect;6)</h3>
    <p>An HSS instance with L=2 levels:</p>
    <ul style="margin:0.5rem 0 0.85rem 1.5rem;line-height:2;font-size:0.88rem;">
      <li><strong>Level 1 (top tree):</strong> signs the public keys of Level 2 trees. Height h1 &rarr; 2^h1 Level 2 trees available.</li>
      <li><strong>Level 2 (bottom trees):</strong> each signs actual messages. Height h2 &rarr; 2^h2 signatures per tree.</li>
      <li><strong>Total capacity:</strong> 2^h1 &times; 2^h2 signatures</li>
    </ul>
    <p style="font-size:0.86rem;" class="text-muted">Step through signing below. The Level&nbsp;2 tree fills one leaf per message; when it&rsquo;s full, Level&nbsp;1 signs a fresh Level&nbsp;2 tree&rsquo;s public key (a <em>roll-over</em>) and signing continues &mdash; the mechanism that lets HSS exceed one tree&rsquo;s 2<sup>h</sup> limit.</p>
    <div class="hss-diagram">
      <div class="hss-level-label">Level 1 Tree (h1=3, 8 slots) &mdash; signs Level 2 public keys</div>
      <div class="hss-row" id="hss-l1-row"></div>
      <div class="hss-connector"></div>
      <div class="hss-level-label">Current Level 2 Tree (h2=3, 8 slots) &mdash; signs messages</div>
      <div class="hss-row" id="hss-l2-row"></div>
      <div class="hss-state-display" id="hss-state-line"></div>
    </div>
    <div class="flex-row" style="margin-top:0.85rem;">
      <button class="btn btn-primary" id="hss-sign-1">Sign 1 message</button>
      <button class="btn btn-secondary" id="hss-sign-8">Fill current L2 (+8)</button>
      <button class="btn btn-secondary" id="hss-reset">Reset</button>
    </div>
    <div id="hss-rollover" class="info-box hidden mt-2" role="status">↻ <strong>Roll-over:</strong> the Level&nbsp;2 tree filled up, so Level&nbsp;1 signed a brand-new Level&nbsp;2 tree&rsquo;s public key. Signing continues seamlessly on the fresh tree.</div>
    <div id="hss-full" class="warn-box hidden mt-2" role="status">🔒 <strong>HSS instance exhausted</strong> &mdash; all ${HSS_CAP} signatures used (2<sup>h1</sup> × 2<sup>h2</sup>). A real deployment sizes h1/h2 for the device lifetime; h1=h2=10 gives over a million.</div>
  </div>
  <div class="card">
    <h3>D3 &mdash; HSS signing process</h3>
    <ol style="margin:0.5rem 0 0.85rem 1.5rem;line-height:2.2;font-size:0.88rem;">
      <li>Use the current Level 2 tree to sign the message (normal LMS signing).</li>
      <li>When the Level 2 tree is exhausted, use the Level 1 tree to sign the new Level 2 tree's public key. This happens once per Level 2 tree.</li>
      <li>HSS signature = (Level 1 LMS-sig on Level 2 PK) &#x2016; (Level 2 LMS-sig on message).</li>
      <li>Verification: verify Level 1 sig on Level 2 PK using Level 1 root, then verify Level 2 sig on message using Level 2 PK.</li>
    </ol>
    <div class="info-box"><strong>Example capacity:</strong> HSS with L=2, h1=10, h2=10 supports 2^10 &times; 2^10 = <strong>1,048,576 signatures</strong> &mdash; sufficient for the entire firmware update lifetime of most deployed devices. Signature size &asymp; 2 &times; LMS-sig = ~3.4 KB at h=10.</div>
  </div>
</section>

<section class="section" id="section-e">
  <div class="section-header">
    <span class="section-tag">E</span>
    <h2>Where LMS/HSS is deployed</h2>
  </div>
  <div class="card">
    <h3>E1 &mdash; CNSA 2.0</h3>
    <p>The NSA's Commercial National Security Algorithm Suite 2.0 (published September 2022) requires LMS or XMSS for software and firmware signing in national security systems, with a transition deadline of 2025&ndash;2030 depending on system classification. CNSA 2.0 specifies LMS and XMSS as the only approved post-quantum signature schemes for these use cases &mdash; ML-DSA (Dilithium, FIPS 204) is approved for other signature uses but is <em>not</em> approved for firmware signing in CNSA 2.0 contexts.</p>
    <div class="info-box">The CNSA 2.0 guidance applies to National Security Systems (NSS) and contractors in the U.S. defense industrial base.</div>
  </div>
  <div class="card">
    <h3>E2 &mdash; Secure boot and firmware signing</h3>
    <p>LMS is well-suited for firmware signing because:</p>
    <ul style="margin:0.5rem 0 0.85rem 1.5rem;line-height:2;font-size:0.88rem;">
      <li>Firmware updates are infrequent (h=20 supports over 1 million updates)</li>
      <li>State management is straightforward when an HSM with a hardware counter handles it</li>
      <li>Verification requires only hash operations &mdash; no field arithmetic</li>
      <li>Signature size (1,452 bytes at h=10 with LMOTS w=8, or 2,508 bytes at w=4) is acceptable in firmware manifest headers</li>
    </ul>
    <p>Contexts where hash-based signatures are being evaluated or deployed: UEFI Secure Boot (next-generation post-quantum transition), IoT firmware over-the-air updates, automotive ECU firmware signing (ISO/SAE 21434), and avionics software loading in DO-178C compliant systems.</p>
  </div>
  <div class="card">
    <h3>E3 &mdash; Comparison with SPHINCS+ and XMSS</h3>
    <div class="table-wrap">
      <table>
        <caption class="sr-only">Comparison of LMS/HSS, XMSS, and SPHINCS+ post-quantum signature schemes</caption>
        <thead><tr><th scope="col">Property</th><th scope="col">LMS/HSS</th><th scope="col">XMSS/XMSS-MT</th><th scope="col">SPHINCS+</th></tr></thead>
        <tbody>
          <tr><td>Standard</td><td>SP 800-208</td><td>SP 800-208</td><td>FIPS 205</td></tr>
          <tr><td>Stateful</td><td><span class="text-warning">Yes</span></td><td><span class="text-warning">Yes</span></td><td><span class="text-accent">No</span></td></tr>
          <tr><td>Signature size</td><td>1,452 B (h=10, w=8)<br>2,508 B (h=10, w=4)</td><td>2,500 B (h=10, w=16)</td><td>7,856 B (128s)</td></tr>
          <tr><td>Key generation</td><td>Fast</td><td>Faster</td><td>Very fast</td></tr>
          <tr><td>Security assumption</td><td>Hash functions</td><td>Hash functions</td><td>Hash functions</td></tr>
          <tr><td>CNSA 2.0 approved</td><td><span class="text-accent">Yes</span></td><td><span class="text-accent">Yes</span></td><td><span class="text-muted">Different use case</span></td></tr>
        </tbody>
      </table>
    </div>
    <p class="text-muted" style="font-size:0.82rem;margin-top:0.5rem;">SPHINCS+ eliminates state at the cost of larger signatures. LMS/HSS is preferred when state can be managed securely. XMSS has similar properties to LMS but uses a different tree construction; both are standardized in NIST SP 800-208.</p>
  </div>
  <div class="card">
    <h3>Cross-references</h3>
    <div style="display:flex;flex-wrap:wrap;gap:0.5rem;font-size:0.84rem;">
      <a href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" target="_blank" rel="noopener">SPHINCS+ Ledger &#8599;</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-merkle-vault/" target="_blank" rel="noopener">Merkle Vault &#8599;</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noopener">Dilithium Seal &#8599;</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-falcon-seal/" target="_blank" rel="noopener">Falcon Seal &#8599;</a>
      <a href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noopener">crypto-lab home &#8599;</a>
    </div>
  </div>
</section>

</div>
</main>

<footer class="site-footer">
  <div class="container">
    <div class="footer-links">
      <a href="https://csrc.nist.gov/publications/detail/sp/800-208/final" target="_blank" rel="noopener">NIST SP 800-208</a>
      <a href="https://datatracker.ietf.org/doc/rfc8554/" target="_blank" rel="noopener">RFC 8554</a>
      <a href="https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_10-MAY-2023.PDF" target="_blank" rel="noopener">CNSA 2.0</a>
      <a href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noopener">crypto-lab portfolio</a>
    </div>
    <div class="footer-links">
      Related demos:
      <a href="https://systemslibrarian.github.io/crypto-lab-lms-xmss/" target="_blank" rel="noopener">crypto-lab-lms-xmss</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" target="_blank" rel="noopener">crypto-lab-sphincs-ledger</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-merkle-vault/" target="_blank" rel="noopener">crypto-lab-merkle-vault</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noopener">crypto-lab-dilithium-seal</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-falcon-seal/" target="_blank" rel="noopener">crypto-lab-falcon-seal</a>
    </div>
    <p>"So whether you eat or drink or whatever you do, do it all for the glory of God." &mdash; 1 Corinthians 10:31</p>
  </div>
</footer>
`;
}

// ============================================================
// UI helpers
// ============================================================

function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function updateKeyGrid() {
  if (!tree) return;
  for (let i = 0; i < LEAF_COUNT; i++) {
    const cell = el<HTMLElement>(`key-cell-${i}`);
    if (!cell) continue;
    cell.className = 'key-cell';
    let state = 'available';
    if (reuseDetected && i === reuseLeafIndex) {
      cell.classList.add('reused');
      state = 'reused — compromised';
    } else if (tree.otsKeys[i].used) {
      cell.classList.add('used');
      state = 'used';
    }
    if (i === tree.nextIndex && !reuseDetected && tree.nextIndex < LEAF_COUNT) {
      cell.classList.add('current');
      state = 'next to use';
    }
    cell.setAttribute('aria-label', `Key ${i}: ${state}`);
    cell.setAttribute('data-tooltip', `key ${i}: ${toHex(tree.otsKeys[i].K.slice(0, 8))}\u2026`);
  }
}

function updateStateCounter() {
  if (!tree) return;
  const remaining = LEAF_COUNT - tree.nextIndex;
  el('counter-value').textContent = `nextIndex = ${tree.nextIndex}`;
  el('counter-remaining').textContent = `${remaining} signature${remaining !== 1 ? 's' : ''} remaining`;
}

function renderSignWalkthrough(coefs: number[]): string {
  const chips = coefs.slice(0, 16).map((a, i) =>
    `<span class="coef-chip" title="digit ${i} = ${a} (step on chain ${i})">${a.toString(16)}</span>`
  ).join('');
  const rows = coefs.map((a, i) => ({ i, a1: a }));
  return `
    <h4 class="walk-title">How this signature was built</h4>
    <ol class="walk-steps">
      <li><strong>Hash the message.</strong> The text runs through SHA-256 (with a per-leaf domain separator) to a 32-byte digest unique to this message and leaf.</li>
      <li><strong>Split into ${P} digits.</strong> The digest plus a Winternitz checksum becomes ${P} base-16 digits <code>a[0…${P - 1}]</code>, each 0&ndash;15. First 16 (hex):
        <div class="coef-strip">${chips}<span class="coef-more">+${P - 16} more</span></div>
      </li>
      <li><strong>Reveal one node per chain.</strong> For each digit <code>a[i]</code> the signer publishes that chain&rsquo;s value at step <code>a[i]</code> &mdash; the green node. Everything below it stays secret; the verifier re-hashes forward to <code>pk</code>. First ${CHAINS_SHOWN} of ${P} chains (expand for all):
        ${renderChainsCollapsible(rows, 'sign')}
        ${chainLegend('sign')}
      </li>
      <li><strong>Attach the Merkle proof.</strong> ${H} sibling hashes (the auth path) let anyone climb from this leaf to the root &mdash; the single public key for all ${LEAF_COUNT} leaves.</li>
    </ol>
    <hr class="divider">`;
}

function showSignResult(sig: LmsSignature, message: Uint8Array, coefs: number[]) {
  const msgText = new TextDecoder().decode(message);
  const allSigBytes = sig.otsSignature.reduce((a, b) => a + b.length, 0) + sig.authPath.reduce((a, b) => a + b.length, 0);
  el('sign-walkthrough').innerHTML = renderSignWalkthrough(coefs);
  const content = el('sign-result-content');
  content.innerHTML = `
    <div class="result-row"><span class="result-key">Status</span><span class="result-value"><span class="badge badge-valid">&#10003; SIGNATURE PRODUCED</span></span></div>
    <div class="result-row"><span class="result-key">Leaf index</span><span class="result-value accent">${sig.leafIndex}</span></div>
    <div class="result-row"><span class="result-key">Message</span><span class="result-value">${escapeHtml(msgText.slice(0, 80))}${msgText.length > 80 ? '\u2026' : ''}</span></div>
    <div class="result-row"><span class="result-key">Sig size</span><span class="result-value">${allSigBytes} bytes (${P}\u00d7${N} OTS + ${H}\u00d7${N} auth path)</span></div>
    <div class="result-row"><span class="result-key">Root</span><span class="result-value accent">${toHex(tree!.root.slice(0, 16))}\u2026</span></div>
  `;
  el('sign-result').classList.remove('hidden');
  const authDisplay = el('auth-path-display');
  authDisplay.innerHTML = sig.authPath.map((node, level) => `
    <div class="auth-path-node">
      <span class="auth-path-level">level ${level}</span>
      <span class="auth-path-hash">${toHex(node)}</span>
    </div>
  `).join('');
  el('auth-path-card').classList.remove('hidden');
  const verifyMsg = el<HTMLTextAreaElement>('verify-message');
  verifyMsg.value = msgText;
  el<HTMLTextAreaElement>('verify-sig-display').value = toHex(sig.otsSignature[0]) + '\u2026 (+' + (sig.otsSignature.length - 1) + ' more elements)';
  el<HTMLButtonElement>('btn-verify').disabled = false;
}

// ============================================================
// Theme toggle
// ============================================================

function initThemeToggle() {
  const btn = el<HTMLButtonElement>('theme-toggle');
  function applyTheme(theme: string) {
    document.documentElement.setAttribute('data-theme', theme);
    btn.textContent = theme === 'dark' ? '\ud83c\udf19' : '\u2600\ufe0f';
    btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    localStorage.setItem('theme', theme);
  }
  const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
  applyTheme(current);
  btn.addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next);
  });
}

// ============================================================
// Section B — signing
// ============================================================

async function initTree() {
  el('init-overlay').classList.remove('hidden');
  if (document.getElementById('btn-sign')) {
    el<HTMLButtonElement>('btn-sign').disabled = true;
  }
  tree = await generateLmsTree();
  el('init-overlay').classList.add('hidden');
  // Reset all state
  lastSignature = null;
  lastMessage = null;
  reuseDetected = false;
  signingLocked = false;
  reuseCaptures = [];
  reuseEnabled = false;
  const reuseToggle = el<HTMLInputElement>('reuse-toggle');
  if (reuseToggle) reuseToggle.checked = false;
  const reuseLabel = document.getElementById('reuse-toggle-label');
  if (reuseLabel) reuseLabel.textContent = 'Force Key Reuse (disabled)';
  el('reuse-warning').classList.add('hidden');
  el('locked-msg').classList.add('hidden');
  el('reuse-results').classList.add('hidden');
  el('forgery-area').classList.add('hidden');
  el('forgery-result').classList.add('hidden');
  el('forgery-prereq-msg').classList.remove('hidden');
  el<HTMLButtonElement>('btn-sign-b').disabled = true;
  el<HTMLButtonElement>('btn-sign').disabled = false;
  el('signing-panel').classList.remove('signing-locked');
  el('exhausted-msg').classList.add('hidden');
  updateKeyGrid();
  updateStateCounter();
}

function bindSigningEvents() {
  el<HTMLButtonElement>('btn-sign').addEventListener('click', async () => {
    if (!tree || signingLocked) return;
    if (tree.nextIndex >= LEAF_COUNT) {
      el('exhausted-msg').classList.remove('hidden');
      el<HTMLButtonElement>('btn-sign').disabled = true;
      return;
    }
    const btn = el<HTMLButtonElement>('btn-sign');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Signing\u2026';
    try {
      const msgText = el<HTMLTextAreaElement>('sign-message').value;
      const msgBytes = new TextEncoder().encode(msgText);
      const { signature, updatedTree } = await lmsSign(tree, msgBytes);
      tree = updatedTree;
      lastSignature = signature;
      lastMessage = msgBytes;
      const coefs = await getMsgCoefficients(msgBytes, tree.id, signature.leafIndex, signature.C);
      updateKeyGrid();
      updateStateCounter();
      showSignResult(signature, msgBytes, coefs);
      if (tree.nextIndex >= LEAF_COUNT) {
        el('exhausted-msg').classList.remove('hidden');
      }
    } catch (err) {
      el('sign-result-content').innerHTML = `<span class="text-danger">${(err as Error).message}</span>`;
      el('sign-result').classList.remove('hidden');
    } finally {
      btn.disabled = (tree?.nextIndex ?? 0) >= LEAF_COUNT || signingLocked;
      btn.innerHTML = '&#9997; Sign Message';
    }
  });

  el<HTMLButtonElement>('btn-verify').addEventListener('click', async () => {
    if (!tree || !lastSignature || !lastMessage) return;
    const btn = el<HTMLButtonElement>('btn-verify');
    btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Verifying\u2026';
    btn.disabled = true;
    try {
      const msgText = el<HTMLTextAreaElement>('verify-message').value;
      const msgBytes = new TextEncoder().encode(msgText);
      const valid = await lmsVerify(msgBytes, lastSignature, tree.id, tree.root);
      el('verify-result-content').innerHTML = (valid
        ? '<span class="badge badge-valid">&#10003; VALID &mdash; signature verified against public key (root)</span>'
        : '<span class="badge badge-invalid">&#10007; INVALID &mdash; message or signature does not match</span>')
        + `<p class="text-muted mt-1" style="font-size:0.78rem;">Verification re-hashes each chain from your signature up to <code>pk</code>, folds the ${P} <code>pk</code> values into the leaf hash, then climbs the ${H} auth-path siblings to a root &mdash; and checks it equals the public key. No secret is ever needed.</p>`;
      el('verify-result').classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '&#10003; Verify';
    }
  });

  el<HTMLButtonElement>('btn-reset-tree').addEventListener('click', async () => {
    if (!confirm('Regenerate the LMS tree? This creates a completely new keypair and resets nextIndex to 0.')) return;
    await initTree();
    el('sign-result').classList.add('hidden');
    el('auth-path-card').classList.add('hidden');
    el('verify-result').classList.add('hidden');
    (el<HTMLTextAreaElement>('verify-message')).value = '';
    (el<HTMLTextAreaElement>('verify-sig-display')).value = '';
    el<HTMLButtonElement>('btn-verify').disabled = true;
  });
}

// ============================================================
// Section C — reuse attack
// ============================================================

function bindReuseEvents() {
  const toggle = el<HTMLInputElement>('reuse-toggle');
  toggle.addEventListener('change', () => {
    reuseEnabled = toggle.checked;
    el('reuse-toggle-label').textContent = reuseEnabled
      ? '⚠ Force Key Reuse (ENABLED — for demo only)'
      : 'Force Key Reuse (disabled)';
    el<HTMLButtonElement>('btn-sign-b').disabled = !reuseEnabled || reuseCaptures.length === 0;
  });

  el<HTMLButtonElement>('btn-sign-a').addEventListener('click', async () => {
    if (!tree) { alert('Tree not ready.'); return; }
    if (tree.nextIndex >= LEAF_COUNT) { alert('Tree exhausted. Reset tree first.'); return; }
    reuseLeafIndex = tree.nextIndex;
    const msgText = el<HTMLTextAreaElement>('reuse-msg-a').value;
    const msgBytes = new TextEncoder().encode(msgText);
    const btn = el<HTMLButtonElement>('btn-sign-a');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" aria-hidden="true"></span><span class="sr-only">Signing…</span>';
    try {
      const { signature, updatedTree } = await lmsSign(tree, msgBytes);
      tree = updatedTree;
      const coefs = await getMsgCoefficients(msgBytes, tree.id, reuseLeafIndex, signature.C);
      reuseCaptures = [{ message: msgBytes, signature, coefs }];
      updateKeyGrid();
      updateStateCounter();
      el<HTMLButtonElement>('btn-sign-b').disabled = !reuseEnabled;
      el('reuse-results').classList.remove('hidden');
      renderReuseCaptures();
    } finally {
      btn.disabled = false;
      btn.innerHTML = 'Sign (consume leaf q)';
    }
  });

  el<HTMLButtonElement>('btn-sign-b').addEventListener('click', async () => {
    if (!tree || reuseCaptures.length === 0 || !reuseEnabled) return;
    const btn = el<HTMLButtonElement>('btn-sign-b');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" aria-hidden="true"></span><span class="sr-only">Reusing leaf…</span>';
    try {
      const k = reuseCaptures.length;
      const msgBytes = new TextEncoder().encode(`Reused signature #${k} — v3.0.${k} malicious build`);
      const { signature } = await lmsSignForceReuse(tree, msgBytes, reuseLeafIndex);
      const coefs = await getMsgCoefficients(msgBytes, tree.id, reuseLeafIndex, signature.C);
      reuseCaptures.push({ message: msgBytes, signature, coefs });
      reuseDetected = true;
      signingLocked = true;
      updateKeyGrid();
      el('reuse-warning').classList.remove('hidden');
      el('locked-msg').classList.remove('hidden');
      el<HTMLButtonElement>('btn-sign').disabled = true;
      el('signing-panel').classList.add('signing-locked');
      renderReuseCaptures();
      if (reuseCaptures.length >= 2) {
        el('forgery-prereq-msg').classList.add('hidden');
        el('forgery-area').classList.remove('hidden');
      }
    } finally {
      btn.disabled = false;
      btn.innerHTML = '↻ Reuse leaf q (+1 leaked signature)';
    }
  });

  el<HTMLButtonElement>('btn-forge').addEventListener('click', async () => {
    if (!tree || reuseCaptures.length < 2) return;
    const btn = el<HTMLButtonElement>('btn-forge');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Computing forgery…';
    try {
      const targetText = el<HTMLTextAreaElement>('forgery-target-msg').value;
      const targetBytes = new TextEncoder().encode(targetText);
      const captures = reuseCaptures.map(c => ({ message: c.message, signature: c.signature }));
      const { forgedSignature, triesUsed, aTarget, reachableFloor } = await forgeFromReuse(
        tree, captures, targetBytes, reuseLeafIndex
      );
      // Verify the forged signature against the REAL public key (tree root).
      const valid = forgedSignature
        ? await lmsVerify(targetBytes, forgedSignature, tree.id, tree.root)
        : false;
      const blocked = aTarget.filter((t, i) => t < reachableFloor[i]).length;
      const forgeRows = reachableFloor
        .map((floor, i) => ({ i, a1: floor, a2: floor, target: aTarget[i] }))
        .sort((x, y) => (x.target - x.a1) - (y.target - y.a1))
        .slice(0, 24);
      const resultDiv = el('forgery-result-content');
      resultDiv.innerHTML = `
        <div class="danger-box" style="margin-bottom:0.75rem;">
          <strong>Forgery result:</strong>
          ${valid
            ? '<span class="badge badge-valid" style="margin-left:0.5rem;">&#10003; FORGED SIGNATURE VERIFIES</span>'
            : `<span class="badge badge-invalid" style="margin-left:0.5rem;">&#10007; No randomizer found in ${triesUsed} tries (reuse the leaf a few more times)</span>`
          }
        </div>
        <p class="text-muted" style="font-size:0.8rem;margin-bottom:0.5rem;">Across the <strong>${reuseCaptures.length}</strong> leaked signatures the attacker holds each chain at its lowest revealed depth <code>floor[i]</code>. They grind the randomizer <code>C</code> until every target digit <code>t &ge; floor[i]</code>, then advance each held value forward to <code>t</code>. This forgery was found after <strong>${triesUsed}</strong> randomizer${triesUsed !== 1 ? 's' : ''}. The <code>t</code> marker is outlined green when reachable:</p>
        ${renderChainsCollapsible(forgeRows, 'reuse')}
        ${chainLegend('reuse')}
        <div class="result-panel">
          <div class="result-row"><span class="result-key">Target msg</span><span class="result-value">${escapeHtml(targetText.slice(0,60))}${targetText.length > 60 ? '…' : ''}</span></div>
          <div class="result-row"><span class="result-key">Leaf reused</span><span class="result-value danger">${reuseLeafIndex} (${reuseCaptures.length} signatures)</span></div>
          <div class="result-row"><span class="result-key">Randomizers tried</span><span class="result-value accent">${triesUsed}</span></div>
          <div class="result-row"><span class="result-key">Verifies vs public key</span><span class="result-value ${valid ? 'accent' : 'warning'}">${valid ? 'YES — forged under the same root' : 'no'}</span></div>
        </div>
        <div class="mt-1" style="font-size:0.78rem;color:var(--text-muted);">Reachable floor vs forged target depth (24 hardest positions) — floor is the lowest depth leaked across reuses, t the forged target:
          ${forgeRows.map(d => `
            <div class="sig-chain-elem ${d.target < d.a1 ? 'differs' : ''}">
              <span class="chain-idx">[${d.i}]</span>
              <span>floor=${d.a1}, t=${d.target} → advance from step ${d.a1}</span>
            </div>
          `).join('')}
          ${blocked > 0 ? `<div class="text-muted" style="margin-top:0.25rem;">${blocked} position(s) still below the floor for this randomizer — reuse the leaf more to lower them.</div>` : ''}
        </div>
      `;
      el('forgery-result').classList.remove('hidden');
    } catch (err) {
      el('forgery-result-content').innerHTML = `<span class="text-danger">${(err as Error).message}</span>`;
      el('forgery-result').classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '&#128275; Demonstrate Forgery';
    }
  });
}

// Per-position minimum depth (floor) across all captured signatures.
function reuseFloor(): number[] {
  const floor = new Array<number>(P).fill(WOTS_STEPS - 1);
  for (const c of reuseCaptures) {
    for (let i = 0; i < P; i++) floor[i] = Math.min(floor[i], c.coefs[i]);
  }
  return floor;
}

function renderReuseCaptures() {
  const k = reuseCaptures.length;
  el('reuse-count-note').innerHTML = k <= 1
    ? 'Enable "Force Key Reuse", then reuse the leaf several times — each click leaks another signature and lowers the attacker’s floor.'
    : `<strong class="text-danger">${k} signatures leaked on leaf ${reuseLeafIndex}.</strong> The attacker now holds each chain at the lowest depth seen across all ${k}. Around eight reuses make forging an arbitrary message reliable.`;

  const maxShow = 20;
  const floor = reuseFloor();
  const recent = reuseCaptures.slice(-2);
  const cols = recent.map((c, idx) => {
    const globalIdx = reuseCaptures.length - recent.length + idx;
    const label = globalIdx === 0 ? 'First signature' : `Reused signature #${globalIdx}`;
    return `<div class="sig-compare-col">
      <h4>${label} — depth a[i]</h4>
      ${Array.from({ length: Math.min(P, maxShow) }, (_, i) => `
        <div class="sig-chain-elem ${c.coefs[i] === floor[i] ? 'differs' : ''}">
          <span class="chain-idx">[${i}]</span>
          <span>step=${c.coefs[i]} | ${toHex(c.signature.otsSignature[i].slice(0,4))}…</span>
        </div>
      `).join('')}
      ${P > maxShow ? `<div class="text-muted" style="font-size:0.72rem;">… +${P - maxShow} more</div>` : ''}
    </div>`;
  }).join('');
  el('sig-compare-display').innerHTML = cols;

  const chainRows = [...floor.keys()]
    .map(i => ({ i, a1: floor[i], a2: floor[i] }))
    .sort((x, y) => x.a1 - y.a1);
  const avgFloor = (floor.reduce((a, b) => a + b, 0) / P).toFixed(1);
  el('reuse-explanation').innerHTML = `
    <span class="text-danger">⚠ ${k} signature${k !== 1 ? 's' : ''} now leaked on this leaf.</span>
    The attacker keeps, per position, the <em>lowest</em> depth seen and can hash <em>forward</em> from it. Every step from <code>floor[i]</code> onward is reachable (average floor now <code>${avgFloor}</code> of ${WOTS_STEPS - 1}). The shaded band below is the forgeable region — it widens with every reuse:
    ${renderChainsCollapsible(chainRows, 'reuse')}
    ${chainLegend('reuse')}
    <span class="text-muted" style="display:block;margin-top:0.5rem;">Why one signature is <em>not</em> enough: to forge you must raise message digits, but the Winternitz checksum forces at least one checksum digit <em>down</em> — below the single depth you know. Each extra reuse lowers the floor at more positions until an arbitrary message lands entirely within reach.</span>
  `;
}

// ============================================================
// Section D — interactive HSS roll-over
// ============================================================

function renderHssGrids() {
  // Grid state is derived from the REAL private key: rootTree.nextIndex counts
  // consumed root leaves (= leaf trees activated), activeLeafTree.nextIndex is
  // the current leaf tree's position.
  const l1Active = hssPriv ? hssPriv.rootTree.nextIndex - 1 : 0; // active leaf-tree slot
  const l2Index = hssPriv ? hssPriv.activeLeafTree.nextIndex : 0;
  const full = hssTotalUsed >= HSS_CAP;
  el('hss-l1-row').innerHTML = Array.from({ length: HSS_L1 }, (_, i) => {
    const used = i < l1Active;
    const active = i === l1Active && !full;
    return `<div class="hss-node ${used ? 'used' : active ? 'active' : ''}" title="L1 slot ${i}">${used ? '✓' : active ? '▶' : i}</div>`;
  }).join('');
  el('hss-l2-row').innerHTML = Array.from({ length: HSS_L2 }, (_, i) => {
    const used = i < l2Index;
    const active = i === l2Index && !full;
    return `<div class="hss-node ${used ? 'used' : active ? 'active' : ''}" title="L2 slot ${i}">${used ? '✓' : active ? '▶' : i}</div>`;
  }).join('');
  const verifyNote = hssTotalUsed > 0
    ? ` | last signature: ${hssLastVerified ? '✓ verified end-to-end' : '✗ verify FAILED'}`
    : '';
  el('hss-state-line').textContent =
    `Active leaf tree: ${Math.max(0, l1Active)} of ${HSS_L1} | Leaf-tree index: ${full ? HSS_L2 : l2Index}/${HSS_L2} | Total signed: ${hssTotalUsed}/${HSS_CAP}${verifyNote}`;
}

async function ensureHss() {
  if (!hssPriv || !hssPub) {
    const { privateKey, publicKey } = await generateHss({ rootH: HSS_ROOT_H, leafH: HSS_LEAF_H, w: W });
    hssPriv = privateKey;
    hssPub = publicKey;
  }
}

async function stepHss(n: number) {
  if (hssBusy) return;
  hssBusy = true;
  try {
    await ensureHss();
    let rolled = false;
    for (let k = 0; k < n; k++) {
      if (hssTotalUsed >= HSS_CAP) break;
      const msg = new TextEncoder().encode(`HSS message #${hssTotalUsed + 1}`);
      const { signature, privateKey, rolledOver } = await hssSign(hssPriv!, msg);
      hssPriv = privateKey;
      // Verify the real HSS signature against the public key every time.
      hssLastVerified = await hssVerify(msg, signature, hssPub!);
      hssTotalUsed++;
      if (rolledOver) rolled = true;
    }
    renderHssGrids();
    el('hss-rollover').classList.toggle('hidden', !rolled || hssTotalUsed >= HSS_CAP);
    el('hss-full').classList.toggle('hidden', hssTotalUsed < HSS_CAP);
  } finally {
    hssBusy = false;
  }
}

function bindHssEvents() {
  el<HTMLButtonElement>('hss-sign-1').addEventListener('click', () => { void stepHss(1); });
  el<HTMLButtonElement>('hss-sign-8').addEventListener('click', () => { void stepHss(HSS_L2); });
  el<HTMLButtonElement>('hss-reset').addEventListener('click', async () => {
    if (hssBusy) return;
    hssBusy = true;
    try {
      const { privateKey, publicKey } = await generateHss({ rootH: HSS_ROOT_H, leafH: HSS_LEAF_H, w: W });
      hssPriv = privateKey;
      hssPub = publicKey;
      hssTotalUsed = 0;
      hssLastVerified = false;
      renderHssGrids();
      el('hss-rollover').classList.add('hidden');
      el('hss-full').classList.add('hidden');
    } finally {
      hssBusy = false;
    }
  });
  renderHssGrids();
}

// ============================================================
// Scroll spy — highlight the active section in the nav
// ============================================================

function initScrollSpy() {
  const navLinks = Array.from(
    document.querySelectorAll<HTMLAnchorElement>('.site-nav a')
  );
  const linkFor = new Map<string, HTMLAnchorElement>();
  for (const link of navLinks) {
    const id = link.getAttribute('href')?.slice(1);
    if (id) linkFor.set(id, link);
  }
  const sections = Array.from(document.querySelectorAll<HTMLElement>('main .section'));
  if (!sections.length || !('IntersectionObserver' in window)) return;

  let activeId = '';
  const setActive = (id: string) => {
    if (id === activeId) return;
    activeId = id;
    for (const link of navLinks) link.removeAttribute('aria-current');
    linkFor.get(id)?.setAttribute('aria-current', 'true');
  };

  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((e) => e.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
      if (visible[0]) setActive(visible[0].target.id);
    },
    { rootMargin: '-45% 0px -45% 0px', threshold: [0, 0.25, 0.5, 1] }
  );
  for (const section of sections) observer.observe(section);
}

// ============================================================
// Main init
// ============================================================

async function main() {
  document.getElementById('app')!.innerHTML = renderApp();
  initThemeToggle();
  bindSigningEvents();
  bindReuseEvents();
  bindHssEvents();
  initScrollSpy();
  await initTree();
}

main();
