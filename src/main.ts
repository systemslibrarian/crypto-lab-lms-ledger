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
  demonstrateForgery,
  getMsgCoefficients,
  toHex,
  H,
  P,
  N,
  W,
} from './lms';
import type { LmsTree, LmsSignature } from './lms';

// App state
let tree: LmsTree | null = null;
let lastSignature: LmsSignature | null = null;
let lastMessage: Uint8Array | null = null;

// Reuse attack state
let reuseEnabled = false;
let reuseLeafIndex = 0;
let reuseSig1: LmsSignature | null = null;
let reuseMsg1Coefs: number[] | null = null;
let reuseSig2: LmsSignature | null = null;
let reuseMsg2Coefs: number[] | null = null;
let reuseDetected = false;
let signingLocked = false;

const LEAF_COUNT = 1 << H;
const WOTS_STEPS = 1 << W; // 16 hash-chain steps (0..15); step 15 is the public key
const CHAINS_SHOWN = 8;    // how many of the p=67 chains to visualize at once

// HSS interactive demo state (Section D)
const HSS_L1 = 8;
const HSS_L2 = 8;
const HSS_CAP = HSS_L1 * HSS_L2; // 64
let hssTotalUsed = 21;           // illustrative starting state: L1 2/8, L2 5/8

// ============================================================
// W-OTS+ hash-chain visualizer (teaching device)
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

// Order positions with the exploitable (differing) ones first; the collapsible
// view shows the first CHAINS_SHOWN and tucks the rest behind a disclosure.
function pickReusePositions(coefs1: number[], coefs2: number[]): number[] {
  const differing: number[] = [];
  const same: number[] = [];
  for (let i = 0; i < coefs1.length; i++) {
    (coefs1[i] !== coefs2[i] ? differing : same).push(i);
  }
  return [...differing, ...same];
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
  <span>Generating LMS tree (32 W-OTS+ keypairs)\u2026</span>
</div>

<a class="skip-link" href="#section-a">Skip to content</a>

<header class="site-header">
  <div class="container">
    <div class="header-titles">
      <h1 class="site-title">LMS <span>/</span> HSS Ledger</h1>
      <p class="site-subtitle">Leighton-Micali Signatures &middot; NIST SP 800-208 &middot; RFC 8554</p>
    </div>
    <button class="theme-toggle" id="theme-toggle" aria-label="Switch to light theme">\ud83c\udf19</button>
  </div>
</header>

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

<section class="section" id="section-a">
  <div class="section-header">
    <span class="section-tag">A</span>
    <h2>What is a stateful hash-based signature?</h2>
  </div>
  <div class="card">
    <h3>A1 &mdash; Hash-based signatures from one-time keys</h3>
    <p>The conceptual foundation is the <strong>Lamport one-time signature</strong>. To sign a 1-bit message <em>b</em>: publish <code>H(sk_b)</code> as the public key. The signature is <code>sk_b</code> &mdash; the verifier checks <code>H(sk_b)</code> matches the published value. The key can only be used once: revealing <code>sk_0</code> to sign a <code>0</code> makes it impossible to later sign a <code>1</code> securely.</p>
    <p><strong>W-OTS+</strong> (Winternitz One-Time Signature, RFC 8554 &sect;3) generalizes this using hash chains. Per the RFC &sect;3.3 signing algorithm: <code>sig[i] = chain(sk[i], 0, a[i])</code> where <code>a[i]</code> is the <em>i</em>-th <em>w</em>-bit coefficient of the message hash. Verification completes the chain: <code>chain(sig[i], a[i], 2^w&minus;1&minus;a[i])</code> must recover <code>pk[i]</code>.</p>
    <div class="chain-primer">
      <p class="chain-primer-caption">A hash chain is a one-way street. Repeatedly hashing turns a secret <code>sk</code> into a public <code>pk</code> over 2<sup>w</sup>=16 steps. You can always walk <em>forward</em> (hash again), but never <em>backward</em>. Signing publishes one node partway along (here, step&nbsp;9); the verifier hashes it forward to <code>pk</code>, while everything below stays secret:</p>
      ${renderChainDiagram([{ i: 0, a1: 9 }], 'sign')}
      ${chainLegend('sign')}
    </div>
    <p><strong>LMS</strong> organizes 2^h W-OTS+ keypairs into a Merkle tree. The root is the LMS public key. An LMS signature includes the OTS signature for the chosen leaf plus an auth path (h sibling hashes) to reconstruct the root. Each leaf is used exactly once.</p>
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
    <p>Stateless schemes like SPHINCS+ (FIPS 205) avoid state but pay in signature size (~8 KB for SPHINCS+-SHA-256-128s). LMS signatures (~1.6 KB at h=10) are 5&times; smaller &mdash; decisive when signatures must fit in firmware manifest headers or be transmitted over constrained IoT channels. Verification requires only hash operations (no field arithmetic).</p>
    <div class="table-wrap">
      <table>
        <caption class="sr-only">Comparison of LMS, SPHINCS+, and Ed25519 signature schemes</caption>
        <thead><tr><th scope="col">Property</th><th scope="col">LMS (h=10)</th><th scope="col">SPHINCS+-128s</th><th scope="col">Ed25519</th></tr></thead>
        <tbody>
          <tr><td>Public key</td><td>64 bytes</td><td>32 bytes</td><td>32 bytes</td></tr>
          <tr><td>Signature</td><td>~1.6 KB</td><td>~8 KB</td><td>64 bytes</td></tr>
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
    <p>W-OTS+ security depends on the signer never revealing more than one signature per leaf. Per RFC 8554 &sect;3.3: <code>sig[i] = chain(sk[i], 0, a[i])</code> &mdash; the signature element at position <em>i</em> is the chain value at step <code>a[i]</code>.</p>
    <p>If leaf <code>q</code> is used twice with different messages:</p>
    <ul style="margin:0.5rem 0 0.85rem 1.5rem;line-height:2;font-size:0.88rem;">
      <li><strong>Sig1[i]</strong> = <code>chain(sk[i], 0, a1[i])</code> &mdash; exposes chain value at step a1[i]</li>
      <li><strong>Sig2[i]</strong> = <code>chain(sk[i], 0, a2[i])</code> &mdash; exposes chain value at step a2[i]</li>
    </ul>
    <p>An attacker observing both signatures can extend either value <em>forward</em> along the hash chain. For any target message with coefficient <code>at[i]</code>: if <code>at[i] &ge; min(a1[i], a2[i])</code>, the attacker constructs the required forged element. Since a random message will have coefficients distributed in <code>[0, 2^w&minus;1]</code>, with high probability most positions are reachable &mdash; producing a valid forgery under the same public key.</p>
    <div class="danger-box"><strong>&#128308; One reuse enables arbitrary forgery.</strong> The entire key tree is compromised &mdash; not just the reused leaf. An attacker can forge signatures for any message they choose.</div>
  </div>
  <div class="card">
    <h3>C2 &mdash; Live reuse demonstration</h3>
    <div class="toggle-row">
      <label class="toggle" for="reuse-toggle"><input type="checkbox" id="reuse-toggle" aria-label="Force key reuse (demonstration only)" aria-describedby="reuse-toggle-label"><span class="toggle-slider" aria-hidden="true"></span></label>
      <span class="toggle-label" id="reuse-toggle-label">Force Key Reuse (disabled)</span>
    </div>
    <div id="reuse-sign-area">
      <div class="form-group">
        <label for="reuse-msg-a">Message A</label>
        <textarea id="reuse-msg-a" rows="2">Firmware v3.0.0 &mdash; authorized release</textarea>
      </div>
      <div class="form-group">
        <label for="reuse-msg-b">Message B (will reuse same leaf when toggle enabled)</label>
        <textarea id="reuse-msg-b" rows="2">Firmware v3.0.0-malware &mdash; backdoor build</textarea>
      </div>
      <div class="flex-row">
        <button class="btn btn-primary" id="btn-sign-a">Sign A</button>
        <button class="btn btn-primary" id="btn-sign-b" disabled>Sign B (same leaf)</button>
      </div>
    </div>
    <div id="reuse-warning" class="warning-banner hidden" role="alert">&#9888; REUSE DETECTED &mdash; Two signatures from the same one-time key. The key is now compromised.</div>
    <div id="locked-msg" class="locked-msg hidden" role="alert">&#128308; KEY COMPROMISED &mdash; Generate a new tree (Reset Tree in Section B) to continue normal signing.</div>
    <div id="reuse-results" class="hidden">
      <hr class="divider">
      <div class="sig-compare" id="sig-compare-display"></div>
      <p class="text-muted mt-1" style="font-size:0.8rem;" id="reuse-explanation"></p>
    </div>
  </div>
  <div class="card" id="forgery-card">
    <h3>C3 &mdash; Forgery demonstration</h3>
    <p style="font-size:0.86rem;" class="text-muted" id="forgery-prereq-msg">Complete the reuse demonstration above (sign Message A and B with the same leaf) to unlock the forgery demo.</p>
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
    <p>NIST SP 800-208 Section 5 requires implementations to <em>"protect against state reuse at all costs"</em> and recommends hardware security modules with monotonic counters that cannot be decremented. The TPM 2.0 specification includes NV counters specifically designed for this purpose &mdash; they can only increment, making rollback physically impossible.</p>
  </div>
</section>

<section class="section" id="section-d">
  <div class="section-header">
    <span class="section-tag">D</span>
    <h2>HSS &mdash; Hierarchical Signature Scheme</h2>
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
    <p>The challenge: generating all 2^h W-OTS+ keypairs upfront (for h=20: 1 million computations). HSS solves this with a multi-level tree hierarchy so only the current leaf tree needs to be precomputed.</p>
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
      <li>Signature size (~1.6 KB at h=10) is acceptable in firmware manifest headers</li>
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
          <tr><td>Signature size</td><td>~1.6 KB (h=10)</td><td>~2.5 KB (h=10)</td><td>~8 KB (128s)</td></tr>
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
    cell.setAttribute('data-tooltip', `key ${i}: ${toHex(tree.otsKeys[i].pkHash.slice(0, 8))}\u2026`);
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
  reuseSig1 = null;
  reuseSig2 = null;
  reuseMsg1Coefs = null;
  reuseMsg2Coefs = null;
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
      const coefs = await getMsgCoefficients(msgBytes, tree.id, signature.leafIndex);
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
      ? '\u26a0 Force Key Reuse (ENABLED \u2014 for demo only)'
      : 'Force Key Reuse (disabled)';
    el<HTMLButtonElement>('btn-sign-b').disabled = !reuseEnabled || !reuseSig1;
  });

  el<HTMLButtonElement>('btn-sign-a').addEventListener('click', async () => {
    if (!tree) { alert('Tree not ready.'); return; }
    if (tree.nextIndex >= LEAF_COUNT) { alert('Tree exhausted. Reset tree first.'); return; }
    reuseLeafIndex = tree.nextIndex;
    const msgText = el<HTMLTextAreaElement>('reuse-msg-a').value;
    const msgBytes = new TextEncoder().encode(msgText);
    const btn = el<HTMLButtonElement>('btn-sign-a');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" aria-hidden="true"></span><span class="sr-only">Signing Message A…</span>';
    try {
      const { signature, updatedTree } = await lmsSign(tree, msgBytes);
      tree = updatedTree;
      reuseSig1 = signature;
      reuseMsg1Coefs = await getMsgCoefficients(msgBytes, tree.id, reuseLeafIndex);
      updateKeyGrid();
      updateStateCounter();
      el<HTMLButtonElement>('btn-sign-b').disabled = !reuseEnabled;
      // Show result
      el('reuse-results').classList.remove('hidden');
      el('sig-compare-display').innerHTML = `<div class="sig-compare-col"><h4>Message A signed</h4><div class="result-panel" style="font-size:0.78rem;">
        <div class="result-row"><span class="result-key">Leaf</span><span class="result-value accent">${signature.leafIndex}</span></div>
        <div class="result-row"><span class="result-key">Msg</span><span class="result-value">${escapeHtml(msgText.slice(0,60))}</span></div>
        <div class="result-row"><span class="result-key">Status</span><span class="result-value"><span class="badge badge-valid">&#10003; VALID</span></span></div>
      </div></div><div class="sig-compare-col"><h4>Message B</h4><p class="text-muted" style="font-size:0.82rem;">Enable "Force Key Reuse" and click Sign B to see the attack.</p></div>`;
    } finally {
      btn.disabled = false;
      btn.innerHTML = 'Sign A';
    }
  });

  el<HTMLButtonElement>('btn-sign-b').addEventListener('click', async () => {
    if (!tree || !reuseSig1 || !reuseEnabled) return;
    const msgText = el<HTMLTextAreaElement>('reuse-msg-b').value;
    const msgBytes = new TextEncoder().encode(msgText);
    const btn = el<HTMLButtonElement>('btn-sign-b');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" aria-hidden="true"></span><span class="sr-only">Signing Message B…</span>';
    try {
      const { signature } = await lmsSignForceReuse(tree, msgBytes, reuseLeafIndex);
      reuseSig2 = signature;
      reuseMsg2Coefs = await getMsgCoefficients(msgBytes, tree.id, reuseLeafIndex);
      reuseDetected = true;
      signingLocked = true;
      updateKeyGrid();
      el('reuse-warning').classList.remove('hidden');
      el('locked-msg').classList.remove('hidden');
      el<HTMLButtonElement>('btn-sign').disabled = true;
      el('signing-panel').classList.add('signing-locked');
      showSigComparison(reuseSig1, signature, reuseMsg1Coefs!, reuseMsg2Coefs!);
      el('forgery-prereq-msg').classList.add('hidden');
      el('forgery-area').classList.remove('hidden');
    } finally {
      btn.innerHTML = 'Sign B (same leaf)';
    }
  });

  el<HTMLButtonElement>('btn-forge').addEventListener('click', async () => {
    if (!tree || !reuseSig1 || !reuseSig2 || !reuseMsg1Coefs || !reuseMsg2Coefs) return;
    const btn = el<HTMLButtonElement>('btn-forge');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Computing forgery\u2026';
    try {
      const targetText = el<HTMLTextAreaElement>('forgery-target-msg').value;
      const targetBytes = new TextEncoder().encode(targetText);
      const { forgedSignature, attackDetails } = await demonstrateForgery(
        tree, reuseSig1, reuseMsg1Coefs, reuseSig2, reuseMsg2Coefs, targetBytes, reuseLeafIndex
      );
      const valid = await lmsVerify(targetBytes, forgedSignature, tree.id, tree.root);
      const unreachable = attackDetails.filter(d => d.method.includes('unreachable')).length;
      const forgeRows = [...attackDetails]
        .sort((a, b) => Number(a.a1 === a.a2) - Number(b.a1 === b.a2))
        .map(d => ({ i: d.i, a1: d.a1, a2: d.a2, target: d.aTarget }));
      const resultDiv = el('forgery-result-content');
      resultDiv.innerHTML = `
        <div class="danger-box" style="margin-bottom:0.75rem;">
          <strong>Forgery result:</strong>
          ${valid
            ? '<span class="badge badge-valid" style="margin-left:0.5rem;">&#10003; FORGED SIGNATURE VERIFIES</span>'
            : `<span class="badge badge-invalid" style="margin-left:0.5rem;">&#10007; Forgery incomplete (${unreachable} position${unreachable !== 1 ? 's' : ''} unreachable)</span>`
          }
        </div>
        <p class="text-muted" style="font-size:0.8rem;margin-bottom:0.5rem;">For the target message, each chain needs a node at step <code>t</code>. If <code>t ≥ min(a1, a2)</code> the attacker hashes forward to it (forgeable); if <code>t</code> falls below both known depths it&rsquo;s blocked. The <code>t</code> marker is outlined green when reachable, red when blocked:</p>
        ${renderChainsCollapsible(forgeRows, 'reuse')}
        ${chainLegend('reuse')}
        <div class="result-panel">
          <div class="result-row"><span class="result-key">Target msg</span><span class="result-value">${escapeHtml(targetText.slice(0,60))}${targetText.length > 60 ? '\u2026' : ''}</span></div>
          <div class="result-row"><span class="result-key">Leaf reused</span><span class="result-value danger">${reuseLeafIndex}</span></div>
          <div class="result-row"><span class="result-key">Reachable</span><span class="result-value accent">${P - unreachable}/${P} positions</span></div>
          ${unreachable > 0 ? `<div class="result-row"><span class="result-key">Note</span><span class="result-value warning">Attacker chooses target message where all coefficients \u2265 min(a1,a2). Easily arranged in practice.</span></div>` : ''}
        </div>
        <div class="mt-1" style="font-size:0.78rem;color:var(--text-muted);">Attack method per position (first 15):
          ${attackDetails.slice(0,15).map(d => `
            <div class="sig-chain-elem ${d.method.includes('unreachable') ? 'differs' : ''}">
              <span class="chain-idx">[${d.i}]</span>
              <span>a1=${d.a1}, a2=${d.a2}, target=${d.aTarget} \u2192 ${d.method}</span>
            </div>
          `).join('')}
          ${attackDetails.length > 15 ? `<div class="text-muted" style="margin-top:0.25rem;">\u2026 and ${attackDetails.length - 15} more</div>` : ''}
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

function showSigComparison(sig1: LmsSignature, sig2: LmsSignature, coefs1: number[], coefs2: number[]) {
  const maxShow = 20;
  const diffs = coefs1.filter((c1, i) => c1 !== coefs2[i]).length;
  el('sig-compare-display').innerHTML = `
    <div class="sig-compare-col">
      <h4>Message A \u2014 sig1[i] at step a1[i]</h4>
      ${Array.from({ length: Math.min(P, maxShow) }, (_, i) => `
        <div class="sig-chain-elem ${coefs1[i] !== coefs2[i] ? 'differs' : ''}">
          <span class="chain-idx">[${i}]</span>
          <span>step=${coefs1[i]} | ${toHex(sig1.otsSignature[i].slice(0,4))}\u2026</span>
        </div>
      `).join('')}
      ${P > maxShow ? `<div class="text-muted" style="font-size:0.72rem;">\u2026 +${P - maxShow} more</div>` : ''}
    </div>
    <div class="sig-compare-col">
      <h4>Message B \u2014 sig2[i] at step a2[i]</h4>
      ${Array.from({ length: Math.min(P, maxShow) }, (_, i) => `
        <div class="sig-chain-elem ${coefs1[i] !== coefs2[i] ? 'differs' : ''}">
          <span class="chain-idx">[${i}]</span>
          <span>step=${coefs2[i]} | ${toHex(sig2.otsSignature[i].slice(0,4))}\u2026</span>
        </div>
      `).join('')}
      ${P > maxShow ? `<div class="text-muted" style="font-size:0.72rem;">\u2026 +${P - maxShow} more</div>` : ''}
    </div>
  `;
  const chainRows = pickReusePositions(coefs1, coefs2).map((i) => ({ i, a1: coefs1[i], a2: coefs2[i] }));
  el('reuse-explanation').innerHTML = `
    <span class="text-danger">\u26a0 ${diffs} of ${P} positions differ between the two signatures.</span>
    At each position the attacker now knows the chain value at <em>two</em> depths &mdash; and can hash <em>forward</em> from the shallower one. So every step from <code>min(a1[i], a2[i])</code> onward is reachable. The shaded band below is that newly forgeable region (differing positions first):
    ${renderChainsCollapsible(chainRows, 'reuse')}
    ${chainLegend('reuse')}
    <span class="text-muted" style="display:block;margin-top:0.5rem;">Why one signature is <em>not</em> enough: to forge you must raise message digits, but the Winternitz checksum forces at least one checksum digit <em>down</em> &mdash; below the single depth you know &mdash; so it stays out of reach. A second reuse lowers your reachable floor at every position, and that protection collapses.</span>
  `;
}

// ============================================================
// Section D — interactive HSS roll-over
// ============================================================

function renderHssGrids() {
  const l1Active = Math.floor(hssTotalUsed / HSS_L2);
  const l2Index = hssTotalUsed % HSS_L2;
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
  el('hss-state-line').textContent =
    `Level 1 index: ${Math.min(l1Active, HSS_L1)}/${HSS_L1} | Level 2 index: ${full ? HSS_L2 : l2Index}/${HSS_L2} | Total used: ${hssTotalUsed}/${HSS_CAP} signatures`;
}

function stepHss(n: number) {
  const before = Math.floor(hssTotalUsed / HSS_L2);
  hssTotalUsed = Math.min(HSS_CAP, hssTotalUsed + n);
  const after = Math.floor(hssTotalUsed / HSS_L2);
  renderHssGrids();
  el('hss-rollover').classList.toggle('hidden', !(after > before) || hssTotalUsed >= HSS_CAP);
  el('hss-full').classList.toggle('hidden', hssTotalUsed < HSS_CAP);
}

function bindHssEvents() {
  el<HTMLButtonElement>('hss-sign-1').addEventListener('click', () => stepHss(1));
  el<HTMLButtonElement>('hss-sign-8').addEventListener('click', () => stepHss(HSS_L2));
  el<HTMLButtonElement>('hss-reset').addEventListener('click', () => {
    hssTotalUsed = 0;
    renderHssGrids();
    el('hss-rollover').classList.add('hidden');
    el('hss-full').classList.add('hidden');
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
