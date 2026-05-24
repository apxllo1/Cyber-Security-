// ===== PAGE NAVIGATION =====
function goTo(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item, .bnav-item').forEach(b => b.classList.remove('active'));

  const page = document.getElementById('page-' + pageId);
  if (page) { page.classList.add('active'); page.scrollTop = 0; }

  document.querySelectorAll('[data-page="' + pageId + '"]').forEach(b => b.classList.add('active'));
}

document.querySelectorAll('.nav-item, .bnav-item').forEach(btn => {
  btn.addEventListener('click', () => goTo(btn.dataset.page));
});

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

// ===== JWT DECODER =====
function decodeJWT() {
  const token = document.getElementById('jwtInput').value.trim();
  if (!token) { setResult('jwtResult', 'Paste a JWT token above.', 'warn'); return; }
  const parts = token.split('.');
  if (parts.length !== 3) { setResult('jwtResult', 'Invalid JWT — must have 3 parts (header.payload.signature)', 'err'); return; }
  try {
    const b64 = s => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + (4 - s.length % 4) % 4, '=')));
    const header  = b64(parts[0]);
    const payload = b64(parts[1]);
    const warnings = [];
    if (header.alg === 'none') warnings.push('CRITICAL: alg=none — signature verification disabled!');
    if (['HS256','HS384'].includes(header.alg)) warnings.push('WARNING: ' + header.alg + ' — vulnerable to algorithm confusion if secret is weak.');
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) warnings.push('EXPIRED: token expired ' + new Date(payload.exp * 1000).toUTCString());
    if (payload.nbf && payload.nbf > now) warnings.push('NOT YET VALID: becomes valid ' + new Date(payload.nbf * 1000).toUTCString());
    let out = '=== HEADER ===\n' + JSON.stringify(header, null, 2);
    out += '\n\n=== PAYLOAD ===\n' + JSON.stringify(payload, null, 2);
    if (payload.iat) out += '\n\nIssued:  ' + new Date(payload.iat * 1000).toUTCString();
    if (payload.exp) out += '\nExpires: ' + new Date(payload.exp * 1000).toUTCString();
    out += '\n\n=== SIGNATURE ===\n' + parts[2];
    out += warnings.length
      ? '\n\n=== SECURITY WARNINGS ===\n' + warnings.join('\n')
      : '\n\n✅ No obvious header/payload issues detected.';
    setResult('jwtResult', out);
  } catch { setResult('jwtResult', 'Error: could not decode — invalid Base64url encoding.', 'err'); }
}

// ===== DNS LOOKUP =====
async function dnsLookup() {
  const domain = document.getElementById('dnsInput').value.trim();
  const type   = document.getElementById('dnsType').value;
  if (!domain) { setResult('dnsResult', 'Enter a domain name.', 'warn'); return; }
  setResult('dnsResult', 'Querying Cloudflare 1.1.1.1...', 'loading');
  try {
    const res  = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, { headers: { Accept: 'application/dns-json' } });
    const data = await res.json();
    if (!data.Answer?.length) { setResult('dnsResult', `No ${type} records found for ${domain}.`); return; }
    const lines = [`${type} records for ${domain}:\n`];
    data.Answer.forEach(r => lines.push(`  ${r.data}  (TTL ${r.TTL}s)`));
    setResult('dnsResult', lines.join('\n'));
  } catch { setResult('dnsResult', 'Error: DNS query failed. Check the domain and try again.', 'err'); }
}

// ===== PASSWORD GENERATOR =====
function updateLenLabel(el) { document.getElementById('passLenLabel').textContent = el.value; }

function generatePassword() {
  const len    = parseInt(document.getElementById('passLen').value) || 16;
  const useLow = document.getElementById('passLow').checked;
  const useUp  = document.getElementById('passUp').checked;
  const useNum = document.getElementById('passNum').checked;
  const useSym = document.getElementById('passSym').checked;
  let charset = '', size = 0;
  if (useLow) { charset += 'abcdefghijklmnopqrstuvwxyz'; size += 26; }
  if (useUp)  { charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; size += 26; }
  if (useNum) { charset += '0123456789'; size += 10; }
  if (useSym) { charset += '!@#$%^&*()-_=+[]{}|;:,.<>?'; size += 28; }
  if (!charset) { setResult('passGenResult', 'Select at least one character type.', 'warn'); return; }
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  const password = Array.from(bytes).map(b => charset[b % charset.length]).join('');
  const entropy  = (len * Math.log2(size)).toFixed(1);
  const strength = entropy < 50 ? 'WEAK' : entropy < 80 ? 'MODERATE' : entropy < 120 ? 'STRONG' : 'VERY STRONG';
  setResult('passGenResult', `${password}\n\nEntropy:  ${entropy} bits\nStrength: ${strength}\nCharset:  ${size} possible chars`);
}

// ===== CIDR CALCULATOR =====
function calcCIDR() {
  const input = document.getElementById('cidrInput').value.trim();
  const m = input.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (!m) { setResult('cidrResult', 'Enter valid CIDR notation, e.g. 192.168.1.0/24', 'warn'); return; }
  const ip = m[1], pre = parseInt(m[2]);
  if (pre < 0 || pre > 32) { setResult('cidrResult', 'Prefix must be 0–32', 'err'); return; }
  const toInt = s => s.split('.').reduce((a, o) => (a << 8) + parseInt(o), 0) >>> 0;
  const toIp  = n => [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
  const mask  = pre === 0 ? 0 : (0xFFFFFFFF << (32 - pre)) >>> 0;
  const net   = (toInt(ip) & mask) >>> 0;
  const bcast = (net | (~mask >>> 0)) >>> 0;
  const hosts = pre >= 31 ? Math.pow(2, 32 - pre) : Math.pow(2, 32 - pre) - 2;
  setResult('cidrResult', [
    `Network:     ${toIp(net)}/${pre}`,
    `Subnet Mask: ${toIp(mask)}`,
    `Wildcard:    ${toIp(~mask >>> 0)}`,
    `Broadcast:   ${toIp(bcast)}`,
    `First Host:  ${pre >= 31 ? toIp(net)   : toIp(net + 1)}`,
    `Last Host:   ${pre >= 31 ? toIp(bcast) : toIp(bcast - 1)}`,
    `Usable Hosts:${hosts.toLocaleString()}`,
    `IP Class:    ${pre <= 8 ? 'A' : pre <= 16 ? 'B' : 'C'}`,
  ].join('\n'));
}

// ===== HASH IDENTIFIER =====
function identifyHash() {
  const h = document.getElementById('hashIdInput').value.trim();
  if (!h) { setResult('hashIdResult', 'Enter a hash string.', 'warn'); return; }
  const types = [
    { name: 'Argon2id',            re: /^\$argon2id\$/,          conf: 'Very High' },
    { name: 'Argon2i',             re: /^\$argon2i\$/,           conf: 'Very High' },
    { name: 'Argon2d',             re: /^\$argon2d\$/,           conf: 'Very High' },
    { name: 'bcrypt',              re: /^\$2[aby]\$\d{2}\$/,     conf: 'Very High' },
    { name: 'scrypt',              re: /^\$7\$/,                  conf: 'Very High' },
    { name: 'MD5-Crypt ($1$)',     re: /^\$1\$/,                  conf: 'Very High' },
    { name: 'SHA-256-Crypt ($5$)', re: /^\$5\$/,                  conf: 'Very High' },
    { name: 'SHA-512-Crypt ($6$)', re: /^\$6\$/,                  conf: 'Very High' },
    { name: 'WordPress (phpass)',  re: /^\$P\$/,                  conf: 'Very High' },
    { name: 'Drupal 7',           re: /^\$S\$/,                  conf: 'Very High' },
    { name: 'SHA-512',            re: /^[a-fA-F0-9]{128}$/,     conf: 'High' },
    { name: 'SHA-256',            re: /^[a-fA-F0-9]{64}$/,      conf: 'High' },
    { name: 'SHA-1',              re: /^[a-fA-F0-9]{40}$/,      conf: 'High' },
    { name: h === h.toUpperCase() && /^[A-F0-9]{32}$/.test(h) ? 'NTLM' : 'MD5', re: /^[a-fA-F0-9]{32}$/, conf: 'High' },
  ];
  const hits = types.filter(t => t.re.test(h));
  if (!hits.length) { setResult('hashIdResult', `No match.\nLength: ${h.length} chars\n\nMay be salted, truncated, or an uncommon format.`); return; }
  setResult('hashIdResult', `${hits.length} possible type(s) for ${h.length}-char hash:\n\n` + hits.map(m => `  ${m.name}  (confidence: ${m.conf})`).join('\n'));
}

// ===== ATTACK PATTERN SCANNER =====
function scanPatterns() {
  const input = document.getElementById('scanInput').value;
  if (!input.trim()) { setResult('scanResult', 'Enter text to scan.', 'warn'); return; }
  const patterns = [
    { name: 'SQL Injection',     re: /('|")\s*(OR|AND)\s*('|"|1|--|;)|(\bUNION\b.*\bSELECT\b|\bDROP\b.*\bTABLE\b|\bINSERT\b.*\bINTO\b)/i },
    { name: 'XSS',               re: /<script[\s>]|javascript:|on\w+\s*=|<iframe|<embed|eval\s*\(/i },
    { name: 'Path Traversal',    re: /(\.\.[/\\]){1,}|%2e%2e[/%\\]|\.\.%2f/i },
    { name: 'Command Injection', re: /[;&|`$]\s*(rm|wget|curl|nc|bash|sh|python|ls|cat|id|whoami)\b|&&|\|\|/i },
    { name: 'LDAP Injection',    re: /[*)(\\|&!~]{3,}|\(\s*[|&]/},
    { name: 'XML Injection',     re: /<!DOCTYPE|<!ENTITY|<!\[CDATA\[|<\?xml/i },
  ];
  const hits = patterns.filter(p => p.re.test(input));
  if (!hits.length) { setResult('scanResult', '✅ No attack patterns detected.\n\nNote: regex scanning supplements — not replaces — proper input validation.'); return; }
  setResult('scanResult', `⚠️  ${hits.length} pattern(s) detected:\n\n` + hits.map(h => `  ❌ ${h.name}`).join('\n') + '\n\nAlways validate server-side and use parameterized queries.');
}

// ===== CVE SEARCH =====
async function searchCVE() {
  const kw = document.getElementById('cveInput').value.trim();
  if (!kw) { setResult('cveResult', 'Enter a keyword to search CVEs.', 'warn'); return; }
  setResult('cveResult', 'Querying NVD database...', 'loading');
  try {
    const res  = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(kw)}&resultsPerPage=5`);
    const data = await res.json();
    if (!data.vulnerabilities?.length) { setResult('cveResult', `No CVEs found for "${kw}"`); return; }
    const lines = [`Found ${data.totalResults.toLocaleString()} total — showing top ${data.vulnerabilities.length}:\n`];
    data.vulnerabilities.forEach(v => {
      const cve  = v.cve;
      const desc = cve.descriptions.find(d => d.lang === 'en')?.value || 'No description';
      const m    = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
      const score = m ? `CVSS ${m.cvssData.baseScore} ${m.cvssData.baseSeverity}` : 'No score';
      lines.push(`${cve.id}  [${score}]`);
      lines.push(`Published: ${new Date(cve.published).toLocaleDateString()}`);
      lines.push(desc.length > 220 ? desc.slice(0, 220) + '…' : desc);
      lines.push('');
    });
    setResult('cveResult', lines.join('\n'));
  } catch { setResult('cveResult', 'Error: NVD API unreachable (rate limit: 5 req/30s). Try again shortly.', 'err'); }
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
