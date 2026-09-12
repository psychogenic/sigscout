import * as openpgp from './lib/openpgp.min.mjs';

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------
// Trusted keys are stored as an array under chrome.storage.local['trustedKeys'].
// Each entry: { id, title, publicKey, fingerprint, keyId, userIDs, algorithm,
//               creationDate, expirationDate, sourceUrl, addedAt }

async function getTrustedKeys() {
  const { trustedKeys } = await chrome.storage.local.get('trustedKeys');
  return Array.isArray(trustedKeys) ? trustedKeys : [];
}

async function saveTrustedKeys(keys) {
  await chrome.storage.local.set({ trustedKeys: keys });
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------

function initTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  tabButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      tabButtons.forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
  });
}

// ---------------------------------------------------------------------------
// Trusted Keys tab
// ---------------------------------------------------------------------------

function originPatternForUrl(urlString) {
  const u = new URL(urlString);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('Only http:// and https:// URLs are supported.');
  }
  return u.origin + '/*';
}

function shortFingerprint(fp) {
  if (!fp) return '';
  const upper = fp.toUpperCase();
  return upper.match(/.{1,4}/g).join(' ');
}

async function fetchKeyMetadata(url) {
  const pattern = originPatternForUrl(url);

  const alreadyGranted = await chrome.permissions.contains({ origins: [pattern] });
  if (!alreadyGranted) {
    const granted = await chrome.permissions.request({ origins: [pattern] });
    if (!granted) {
      throw new Error('Permission to access this site was not granted, so the key could not be fetched.');
    }
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  let response;
  try {
    response = await fetch(url, { signal: controller.signal, credentials: 'omit' });
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('The request timed out.');
    throw new Error('Could not reach that URL: ' + e.message);
  } finally {
    clearTimeout(timeout);
  }
  if (!response.ok) {
    throw new Error('Server responded with ' + response.status + ' ' + response.statusText);
  }

  let json;
  try {
    json = await response.json();
  } catch (e) {
    throw new Error('That URL did not return valid JSON.');
  }

  if (!json || typeof json.title !== 'string' || !json.title.trim()) {
    throw new Error('The JSON is missing a "title" field.');
  }
  if (!json || typeof json.publicKey !== 'string' || !json.publicKey.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
    throw new Error('The JSON is missing a "publicKey" field with an armored PGP public key.');
  }

  return json;
}

async function parseKeyForPreview(armoredKey) {
  let key;
  try {
    key = await openpgp.readKey({ armoredKey });
  } catch (e) {
    throw new Error('This does not look like a valid PGP public key: ' + e.message);
  }
  if (key.isPrivate()) {
    throw new Error(
      'This armored block is a PRIVATE key, not a public key. Refusing to import it — ' +
      'never share or import private keys here.'
    );
  }
  const expirationTime = await key.getExpirationTime();
  return {
    key,
    fingerprint: key.getFingerprint(),
    keyId: key.getKeyID().toHex(),
    userIDs: key.getUserIDs(),
    algorithm: key.getAlgorithmInfo(),
    creationDate: key.getCreationTime(),
    expirationDate: expirationTime === Infinity || expirationTime === null ? null : expirationTime,
    isExpired: expirationTime !== Infinity && expirationTime !== null && expirationTime < new Date(),
  };
}

let pendingKeyImport = null; // holds { metadata, parsed } between fetch and confirm

function showAddKeyForm() {
  document.getElementById('add-key-form').classList.remove('hidden');
  document.getElementById('key-preview').classList.add('hidden');
  document.getElementById('add-key-error').classList.add('hidden');
  document.getElementById('key-url-input').value = '';
  document.getElementById('key-url-input').focus();
}

function hideAddKeyForms() {
  document.getElementById('add-key-form').classList.add('hidden');
  document.getElementById('key-preview').classList.add('hidden');
  pendingKeyImport = null;
}

function renderKeyPreview(metadata, parsed, sourceUrl) {
  const dl = document.getElementById('key-preview-details');
  dl.innerHTML = '';
  const rows = [
    ['Title (from source)', metadata.title, 'plain'],
    ['Key holder(s)', parsed.userIDs.join(', ') || '(none listed)', 'plain'],
    ['Fingerprint', shortFingerprint(parsed.fingerprint), 'mono'],
    ['Key ID', parsed.keyId, 'mono'],
    ['Algorithm', parsed.algorithm.algorithm + ' (' + (parsed.algorithm.bits || parsed.algorithm.curve || '?') + ')', 'plain'],
    ['Created', new Date(parsed.creationDate).toLocaleDateString(), 'plain'],
    ['Expires', parsed.expirationDate ? new Date(parsed.expirationDate).toLocaleDateString() : 'Never', 'plain'],
    ['Source URL', sourceUrl, 'plain'],
  ];
  for (const [label, value, kind] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    if (kind === 'plain') dd.classList.add('plain');
    dd.textContent = value;
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  const warning = document.getElementById('key-preview-warning');
  if (parsed.isExpired) {
    warning.textContent = 'Note: this key has expired. Signatures made with it may no longer verify.';
    warning.classList.remove('hidden');
  } else {
    warning.classList.add('hidden');
  }

  document.getElementById('add-key-form').classList.add('hidden');
  document.getElementById('key-preview').classList.remove('hidden');
}

async function renderTrustedKeysList() {
  const keys = await getTrustedKeys();
  const container = document.getElementById('trusted-keys-list');
  container.innerHTML = '';
  if (keys.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = 'No trusted keys yet. Add one above.';
    container.appendChild(empty);
    return;
  }
  for (const k of keys) {
    const row = document.createElement('div');
    row.className = 'key-row';
    const title = document.createElement('div');
    title.className = 'key-title';
    title.textContent = k.title;
    const meta = document.createElement('div');
    meta.className = 'key-meta';
    meta.textContent = shortFingerprint(k.fingerprint);
    const actions = document.createElement('div');
    actions.className = 'key-actions';
    const removeBtn = document.createElement('button');
    removeBtn.className = 'remove-btn';
    removeBtn.textContent = 'Remove';
    removeBtn.addEventListener('click', async () => {
      const updated = (await getTrustedKeys()).filter((entry) => entry.id !== k.id);
      await saveTrustedKeys(updated);
      renderTrustedKeysList();
    });
    actions.appendChild(removeBtn);
    row.appendChild(title);
    row.appendChild(meta);
    row.appendChild(actions);
    container.appendChild(row);
  }
}

async function renderGrantedOrigins() {
  const container = document.getElementById('granted-origins-list');
  container.innerHTML = '';
  const all = await chrome.permissions.getAll();
  const origins = (all.origins || []).filter((o) => o !== '<all_urls>');
  if (origins.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = 'No sites granted yet.';
    container.appendChild(empty);
    return;
  }
  for (const origin of origins) {
    const row = document.createElement('div');
    row.className = 'origin-row';
    const label = document.createElement('span');
    label.textContent = origin;
    const revokeBtn = document.createElement('button');
    revokeBtn.className = 'revoke-btn';
    revokeBtn.textContent = 'Revoke';
    revokeBtn.addEventListener('click', async () => {
      await chrome.permissions.remove({ origins: [origin] });
      renderGrantedOrigins();
    });
    row.appendChild(label);
    row.appendChild(revokeBtn);
    container.appendChild(row);
  }
}

function initTrustedKeysTab() {
  document.getElementById('add-key-btn').addEventListener('click', showAddKeyForm);
  document.getElementById('cancel-add-key-btn').addEventListener('click', hideAddKeyForms);
  document.getElementById('cancel-preview-btn').addEventListener('click', hideAddKeyForms);

  document.getElementById('fetch-key-btn').addEventListener('click', async () => {
    const urlInput = document.getElementById('key-url-input');
    const errorBox = document.getElementById('add-key-error');
    errorBox.classList.add('hidden');
    const url = urlInput.value.trim();
    if (!url) return;

    try {
      const metadata = await fetchKeyMetadata(url);
      const parsed = await parseKeyForPreview(metadata.publicKey);
      pendingKeyImport = { metadata, parsed, sourceUrl: url };
      renderKeyPreview(metadata, parsed, url);
    } catch (e) {
      errorBox.textContent = e.message;
      errorBox.classList.remove('hidden');
    }
  });

  document.getElementById('confirm-add-key-btn').addEventListener('click', async () => {
    if (!pendingKeyImport) return;
    const { metadata, parsed, sourceUrl } = pendingKeyImport;
    const keys = await getTrustedKeys();
    const withoutDuplicate = keys.filter((k) => k.id !== parsed.fingerprint);
    withoutDuplicate.push({
      id: parsed.fingerprint,
      title: metadata.title,
      publicKey: metadata.publicKey,
      fingerprint: parsed.fingerprint,
      keyId: parsed.keyId,
      userIDs: parsed.userIDs,
      algorithm: parsed.algorithm,
      creationDate: parsed.creationDate,
      expirationDate: parsed.expirationDate,
      sourceUrl,
      addedAt: Date.now(),
    });
    await saveTrustedKeys(withoutDuplicate);
    hideAddKeyForms();
    renderTrustedKeysList();
  });
}

// ---------------------------------------------------------------------------
// Verify tab — page scanning + signature verification
// ---------------------------------------------------------------------------

// This function is serialized and injected into the target page, so it must
// be fully self-contained (no references to anything outside its own body).
function scanPageForPGPBlocks() {
  const regex = /-----BEGIN PGP SIGNED MESSAGE-----[\s\S]*?-----END PGP SIGNATURE-----/g;
  const root = document.body || document.documentElement;
  const text = root ? root.textContent : '';
  // to deal with markdown pages that require extra dashes 
  // for cut & paste
  const normalized = text.replace(/-{6,}/g, '-----');
  return normalized.match(regex) || [];
}

// Also self-contained for the same reason as above. Draws a small labeled
// banner just before each signed block found on the page. Insertions are
// done in reverse document order so earlier offsets stay valid.
function annotatePGPBlocksOnPage(results) {
  const regex = /-----BEGIN PGP SIGNED MESSAGE-----[\s\S]*?-----END PGP SIGNATURE-----/g;
  const root = document.body;
  if (!root) return;

  root.querySelectorAll('.pgpverify-banner').forEach((el) => el.remove());

  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const p = node.parentElement;
      if (!p) return NodeFilter.FILTER_REJECT;
      if (p.tagName === 'SCRIPT' || p.tagName === 'STYLE') return NodeFilter.FILTER_REJECT;
      if (p.closest('.pgpverify-banner')) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });

  const nodes = [];
  let fullText = '';
  let n;
  while ((n = walker.nextNode())) {
    nodes.push({ node: n, start: fullText.length });
    fullText += n.data;
  }

  function locate(globalOffset) {
    for (let i = nodes.length - 1; i >= 0; i--) {
      if (globalOffset >= nodes[i].start) {
        return { node: nodes[i].node, localOffset: globalOffset - nodes[i].start };
      }
    }
    return null;
  }

  function makeBanner(status, label) {
    const div = document.createElement('div');
    div.className = 'pgpverify-banner';
    div.textContent = label;
    const colors = {
      valid: ['#0F6B52', '#E7F3EE'],
      invalid: ['#A6341C', '#FBEAE5'],
      unknown: ['#9A6B12', '#FBF1DD'],
    };
    const [fg, bg] = colors[status] || colors.unknown;
    div.setAttribute(
      'style',
      'all:revert; display:block; font-family: ui-monospace, monospace; font-size:12px; ' +
      'padding:6px 10px; margin:6px 0; border-left:4px solid ' + fg + '; ' +
      'background:' + bg + '; color:' + fg + '; border-radius:2px;'
    );
    return div;
  }

  const matches = [];
  let match;
  regex.lastIndex = 0;
  let idx = 0;
  while ((match = regex.exec(fullText)) !== null) {
    matches.push({ index: match.index, result: results[idx++] });
  }

  // Reverse order: inserting later matches first never invalidates the
  // node/offset of matches that occur earlier in the document.
  for (let i = matches.length - 1; i >= 0; i--) {
    const { index, result } = matches[i];
    if (!result) continue;
    const loc = locate(index);
    if (!loc) continue;
    const label =
      result.status === 'valid'
        ? 'PGP signature verified: signed by "' + result.matchedTitle + '"'
        : result.status === 'invalid'
        ? 'PGP signature check FAILED:  ' + (result.detail || 'content may have been altered.')
        : 'PGP signature present, but not from a trusted key' + (result.keyId ? ' (key ID ' + result.keyId + ')' : '');
    const banner = makeBanner(result.status, label);
    const r = document.createRange();
    r.setStart(loc.node, loc.localOffset);
    r.collapse(true);
    r.insertNode(banner);
  }
}

async function verifyBlocks(blocks, trustedKeys) {
  const parsed = [];
  for (const tk of trustedKeys) {
    try {
      const keyObj = await openpgp.readKey({ armoredKey: tk.publicKey });
      parsed.push({ entry: tk, keyObj });
    } catch (e) {
      // Skip a corrupted stored key rather than failing the whole scan.
      console.warn('Stored key could not be parsed, skipping:', tk.title, e);
    }
  }
  const keyIdToEntry = new Map();
  for (const p of parsed) {
    for (const k of p.keyObj.getKeys()) {
      keyIdToEntry.set(k.getKeyID().toHex(), p.entry);
    }
  }
  const allPublicKeyObjs = parsed.map((p) => p.keyObj);
  const invalidresults = [];
  const results = [];
  for (const block of blocks) {
    const preview = block.split('\n').slice(0, 4).join('\n');
    try {
      const cleartextMessage = await openpgp.readCleartextMessage({ cleartextMessage: block });

      if (allPublicKeyObjs.length === 0) {
        results.push({ status: 'unknown', preview, detail: 'No trusted keys configured yet.' });
        continue;
      }

      const verificationResult = await openpgp.verify({
        message: cleartextMessage,
        verificationKeys: allPublicKeyObjs,
      });

      let outcome = null;
      for (const sig of verificationResult.signatures) {
        const keyIdHex = sig.keyID.toHex();
        try {
          await sig.verified;
          const matchedEntry = keyIdToEntry.get(keyIdHex);
          outcome = {
            status: 'valid',
            preview,
            keyId: keyIdHex,
            matchedTitle: matchedEntry ? matchedEntry.title : '(unknown trusted entry)',
          };
          break;
        } catch (err) {
          const untrusted = /Could not find signing key/i.test(err.message || '');
          outcome = {
            status: untrusted ? 'unknown' : 'invalid',
            preview,
            keyId: keyIdHex,
            detail: untrusted
              ? 'Signed by a key that is not in your trusted list.'
              : 'Signature does not match this content — it may have been altered since signing, or the block is corrupted.',
          };
        }
      }
      results.push(outcome);
    } catch (e) {
      invalidresults.push({
        status: 'invalid',
        preview,
        detail: 'Could not parse this as a PGP cleartext-signed message: ' + e.message,
      });
    }
  }
  if (! results.length ) {
    return invalidresults;
  }
  return results;
}

function setScanStatus(text) {
  document.getElementById('scan-status').textContent = text;
}

function renderScanResults(results) {
  const container = document.getElementById('scan-results');
  container.innerHTML = '';
  for (const r of results) {
    const row = document.createElement('div');
    row.className = 'result-row status-' + r.status;
    const status = document.createElement('div');
    status.className = 'result-status';
    status.textContent =
      r.status === 'valid' ? 'Verified' : r.status === 'invalid' ? 'Failed' : 'Unrecognized signer';
    const detail = document.createElement('div');
    detail.className = 'result-detail';
    detail.textContent =
      r.status === 'valid' ? 'Signed by trusted key: ' + r.matchedTitle : r.detail || '';
    const preview = document.createElement('div');
    preview.className = 'result-preview';
    preview.textContent = r.preview + (r.preview.length < (r.fullLength || 0) ? '...' : '');
    row.appendChild(status);
    row.appendChild(detail);
    row.appendChild(preview);
    container.appendChild(row);
  }
}

function initVerifyTab() {
  document.getElementById('scan-btn').addEventListener('click', async () => {
    const container = document.getElementById('scan-results');
    container.innerHTML = '';
    setScanStatus('Scanning page...');

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      setScanStatus('No active tab found.');
      return;
    }

    let injectionResults;
    try {
      injectionResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: scanPageForPGPBlocks,
      });
    } catch (e) {
      setScanStatus(
        'Could not scan this page. Browser-internal pages (chrome://..., the Web Store, etc.) cannot be scanned.'
      );
      return;
    }

    const blocks = (injectionResults && injectionResults[0] && injectionResults[0].result) || [];
    if (blocks.length === 0) {
      setScanStatus('No PGP-signed blocks found on this page.');
      return;
    }

    setScanStatus('Found ' + blocks.length + ' signed block(s). Verifying...');
    const trustedKeys = await getTrustedKeys();
    const results = await verifyBlocks(blocks, trustedKeys);
    renderScanResults(results);
    setScanStatus('Done — ' + blocks.length + ' block(s) checked.');

    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: annotatePGPBlocksOnPage,
        args: [results],
      });
    } catch (e) {
      console.warn('Could not annotate the page (non-fatal):', e);
    }
  });
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

initTabs();
initTrustedKeysTab();
initVerifyTab();
renderTrustedKeysList();
renderGrantedOrigins();
