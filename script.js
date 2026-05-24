// ===== HASH GENERATOR =====
async function genHash(algo) {
  const input = document.getElementById('hashInput').value;
  if (!input.trim()) {
    setResult('hashResult', 'Enter some text first.', 'warn');
    return;
  }
  const encoded = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest(algo, encoded);
  const hex = Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  setResult('hashResult', `${algo}:\n${hex}`);
}

// ===== BASE64 =====
function b64Encode() {
  const val = document.getElementById('b64Input').value;
  if (!val.trim()) { setResult('b64Result', 'Enter text first.', 'warn'); return; }
  try {
    setResult('b64Result', btoa(unescape(encodeURIComponent(val))));
  } catch {
    setResult('b64Result', 'Error: could not encode.', 'err');
  }
}

function b64Decode() {
  const val = document.getElementById('b64Input').value;
  if (!val.trim()) { setResult('b64Result', 'Enter Base64 first.', 'warn'); return; }
  try {
    setResult('b64Result', decodeURIComponent(escape(atob(val.trim()))));
  } catch {
    setResult('b64Result', 'Error: invalid Base64 string.', 'err');
  }
}

// ===== PASSWORD STRENGTH =====
function checkPass() {
  const pass = document.getElementById('passInput').value;
  const bar  = document.getElementById('strengthBar');
  const res  = document.getElementById('passResult');

  if (!pass) {
    bar.style.width = '0';
    bar.className = 'strength-bar';
    res.textContent = 'Enter a password above...';
    res.style.color = '';
    const lbl = document.getElementById('strengthLabel');
    if (lbl) { lbl.textContent = '—'; lbl.style.color = ''; }
    return;
  }

  let score = 0;
  const checks = [
    [/.{8,}/,           'At least 8 characters'],
    [/.{12,}/,          'At least 12 characters'],
    [/[A-Z]/,           'Uppercase letter'],
    [/[a-z]/,           'Lowercase letter'],
    [/[0-9]/,           'Number'],
    [/[^A-Za-z0-9]/,   'Special character'],
  ];

  const passed = [];
  const failed = [];
  checks.forEach(([re, label]) => {
    if (re.test(pass)) { score++; passed.push(label); }
    else { failed.push(label); }
  });

  const pct = Math.round((score / checks.length) * 100);
  bar.style.width = pct + '%';

  bar.className = 'strength-bar';
  let label, color;
  if (pct <= 33)      { label = 'WEAK';   bar.classList.add('weak');   color = '#ef4444'; }
  else if (pct <= 50) { label = 'FAIR';   bar.classList.add('fair');   color = '#f59e0b'; }
  else if (pct <= 75) { label = 'GOOD';   bar.classList.add('good');   color = '#3b82f6'; }
  else                { label = 'STRONG'; bar.classList.add('strong'); color = '#10b981'; }

  res.style.color = color;

  const labelEl = document.getElementById('strengthLabel');
  if (labelEl) { labelEl.textContent = label; labelEl.style.color = color; }

  const missing = failed.length ? `Missing: ${failed.join(', ')}` : 'All checks passed!';
  res.textContent = `${label} (${pct}%) — ${missing}`;
}

// ===== IP LOOKUP =====
async function lookupIP() {
  const ip = document.getElementById('ipInput').value.trim();
  const url = ip ? `https://ipinfo.io/${ip}/json` : 'https://ipinfo.io/json';
  await fetchIP(url);
}

async function myIP() {
  document.getElementById('ipInput').value = '';
  await fetchIP('https://ipinfo.io/json');
}

async function fetchIP(url) {
  setResult('ipResult', 'Looking up...', 'loading');
  try {
    const res  = await fetch(url);
    const data = await res.json();
    if (data.bogon) {
      setResult('ipResult', 'Private / bogon IP — not routable on the public internet.');
      return;
    }
    const lines = [
      `IP:       ${data.ip       || 'N/A'}`,
      `Hostname: ${data.hostname || 'N/A'}`,
      `City:     ${data.city     || 'N/A'}`,
      `Region:   ${data.region   || 'N/A'}`,
      `Country:  ${data.country  || 'N/A'}`,
      `Org:      ${data.org      || 'N/A'}`,
      `Timezone: ${data.timezone || 'N/A'}`,
    ];
    setResult('ipResult', lines.join('\n'));
  } catch {
    setResult('ipResult', 'Error: could not reach ipinfo.io. Check your connection.', 'err');
  }
}

// ===== HELPERS =====
function setResult(id, text, type) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.style.color = type === 'err'     ? '#ef4444'
                 : type === 'warn'    ? '#f59e0b'
                 : type === 'loading' ? '#a09cb3'
                 : '#6d28d9';
}

function copyResult(id) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector(`[onclick="copyResult('${id}')"]`);
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}
