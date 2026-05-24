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

// ===== URL ANALYZER =====
async function analyzeURL() {
  let raw = document.getElementById('urlInput').value.trim();
  if (!raw) { setResult('urlResult', 'Enter a URL to analyze.', 'warn'); return; }
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  setResult('urlResult', 'Analyzing...', 'loading');
  let url;
  try { url = new URL(raw); } catch { setResult('urlResult', 'Invalid URL format — make sure it is a valid URL.', 'err'); return; }
  const domain = url.hostname.toLowerCase();
  const out = [];
  out.push('=== URL STRUCTURE ===');
  out.push(`Protocol:  ${url.protocol}`);
  out.push(`Domain:    ${domain}`);
  if (url.port)              out.push(`Port:      ${url.port}`);
  if (url.pathname !== '/')  out.push(`Path:      ${url.pathname}`);
  if (url.search)            out.push(`Params:    ${url.search}`);
  if (url.hash)              out.push(`Fragment:  ${url.hash}`);
  out.push(`Length:    ${raw.length} chars`);
  out.push('\n=== SECURITY CHECKS ===');
  const flags = [], safe = [];
  if (url.protocol === 'https:') safe.push('✅ HTTPS — encrypted connection');
  else flags.push('🚨 HTTP — unencrypted, vulnerable to MITM');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) flags.push('🚨 Raw IP used as domain — real identity hidden');
  const shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','adf.ly','v.gd','tr.im','rb.gy','cutt.ly','shorturl.at','tiny.cc','b.link','dub.sh','lnkd.in','t.me','reurl.cc'];
  if (shorteners.some(s => domain === s || domain.endsWith('.'+s))) flags.push('⚠️  URL shortener — true destination concealed');
  if (domain.includes('xn--')) flags.push('🚨 Punycode domain — possible homograph/lookalike attack');
  const parts = domain.split('.');
  if (parts.length > 4) flags.push(`⚠️  Deep subdomain (${parts.length-2} levels) — may obscure the real domain`);
  const brands = ['paypal','amazon','google','microsoft','apple','netflix','facebook','roblox','discord','steam','bank','secure','login','verify','update','account','signin','wallet','crypto','binance','coinbase','robux'];
  const found = brands.filter(b => domain.includes(b));
  if (found.length) flags.push(`⚠️  Brand keyword in domain: "${found.join(', ')}" — possible phishing`);
  const tld = parts[parts.length-1];
  if (['tk','ml','ga','cf','gq','xyz','top','icu','club','work','link','live'].includes(tld)) flags.push(`⚠️  Suspicious TLD: .${tld} — free/high-abuse TLD`);
  const dangerExt = ['.exe','.bat','.cmd','.ps1','.vbs','.wsf','.msi','.scr','.pif','.hta','.jar','.sh','.dmg','.pkg'];
  if (dangerExt.some(e => url.pathname.toLowerCase().endsWith(e))) flags.push('🚨 Dangerous file extension in path — likely executable');
  if (/\.(pdf|doc|docx|jpg|png|txt)\.(exe|bat|cmd|ps1|scr|vbs)/i.test(url.pathname)) flags.push('🚨 Double extension trick — disguised executable');
  if (/%00|%0d|%0a/i.test(raw)) flags.push('🚨 Null byte or CRLF injection detected');
  if ((raw.match(/@/g)||[]).length) flags.push('🚨 @ symbol in URL — may be used to spoof the domain');
  if (raw.length > 250) flags.push(`⚠️  Very long URL (${raw.length} chars) — may hide true destination`);
  const redirectParams = ['redirect','url','goto','next','return','returnurl','callback','destination','target','redir'];
  const foundParams = [];
  for (const [k] of url.searchParams) if (redirectParams.some(r => k.toLowerCase().includes(r))) foundParams.push(k);
  if (foundParams.length) flags.push(`⚠️  Open redirect param(s): ${foundParams.join(', ')}`);
  for (const [k, v] of url.searchParams) {
    if (v.length > 20 && /^[A-Za-z0-9+/]+=*$/.test(v)) {
      try { const d = atob(v); if (/[a-zA-Z]{5,}/.test(d)) flags.push(`⚠️  Base64 in param "${k}" → ${d.slice(0,80)}`); } catch {}
    }
  }
  flags.forEach(f => out.push(f));
  safe.forEach(s => out.push(s));
  if (!flags.length) out.push('✅ No suspicious structural patterns detected');
  out.push('\n=== DNS / IP INFO ===');
  try {
    const ac1 = new AbortController();
    const t1 = setTimeout(() => ac1.abort(), 7000);
    const dnsRes = await fetch(
      `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { Accept: 'application/dns-json' }, signal: ac1.signal }
    );
    clearTimeout(t1);
    if (!dnsRes.ok) throw new Error(`DNS API returned ${dnsRes.status}`);
    const dnsData = await dnsRes.json();
    if (dnsData.Status === 3) {
      out.push('NXDOMAIN — this domain does not exist in DNS.');
      flags.push('🚨 Domain does not exist (NXDOMAIN)');
    } else {
      const ips = (dnsData.Answer || []).map(r => r.data).filter(d => /^\d{1,3}\.\d/.test(d));
      if (ips.length) {
        out.push(`DNS (A):   ${ips.join(', ')}`);
        try {
          const ac2 = new AbortController();
          const t2 = setTimeout(() => ac2.abort(), 5000);
          const ipRes = await fetch(`https://ipinfo.io/${ips[0]}/json`, { signal: ac2.signal });
          clearTimeout(t2);
          const ipData = await ipRes.json();
          if (!ipData.bogon) {
            out.push(`Location:  ${[ipData.city,ipData.region,ipData.country].filter(Boolean).join(', ')||'N/A'}`);
            out.push(`ISP/Org:   ${ipData.org||'N/A'}`);
            out.push(`Timezone:  ${ipData.timezone||'N/A'}`);
            if (ipData.hostname) out.push(`Rev DNS:   ${ipData.hostname}`);
          } else out.push('IP is private/bogon (not a public address).');
        } catch (e) {
          out.push(`IP geo: ${e.name==='AbortError'?'timed out (5s)':'lookup failed — '+e.message}`);
        }
      } else {
        const cnames = (dnsData.Answer||[]).map(r=>r.data).filter(d=>/[a-z]/i.test(d));
        out.push(cnames.length ? `No A record — CNAME to: ${cnames.join(', ')}` : 'No A records found for this domain.');
      }
    }
  } catch (e) {
    out.push(`DNS lookup failed: ${e.name==='AbortError'?'timed out (7s) — check connection':e.message}`);
  }
  out.push('\n=== VERDICT ===');
  const crit = flags.filter(f => f.startsWith('🚨')).length;
  const warn = flags.filter(f => f.startsWith('⚠️')).length;
  if (crit >= 2)     out.push(`🚨 HIGH RISK — ${crit} critical issue(s) + ${warn} warning(s)`);
  else if (crit)     out.push(`🚨 HIGH RISK — ${crit} critical issue(s) detected`);
  else if (warn > 1) out.push(`⚠️  SUSPICIOUS — ${warn} warning(s) — investigate before sharing`);
  else if (warn)     out.push('⚠️  LOW CONCERN — 1 minor flag — verify before trusting');
  else               out.push('✅ APPEARS SAFE — No significant threats found');
  setResult('urlResult', out.join('\n'));
}

// ===== CODE DEOBFUSCATOR =====
function deobfuscate() {
  const input = document.getElementById('deobfInput').value.trim();
  if (!input) { setResult('deobfResult', 'Paste obfuscated code above.', 'warn'); return; }

  const obfType = detectObfuscator(input);
  const loaders = extractLoaders(input);
  let code = input;
  const steps = [];

  for (let pass = 0; pass < 15; pass++) {
    const prev = code;

    // URL decode
    try { const d = decodeURIComponent(code); if (d !== code) { steps.push('URL decode'); code = d; } } catch {}

    // HTML entities
    const ent = code
      .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
      .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'");
    if (ent !== code) { steps.push('HTML entities'); code = ent; }

    // Unicode \uXXXX
    const uni = code.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    if (uni !== code) { steps.push('Unicode \\u'); code = uni; }

    // Hex \xXX
    const hx = code.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    if (hx !== code) { steps.push('Hex \\x'); code = hx; }

    // JS String.fromCharCode(n,n,...)
    const sfc = code.replace(/String\.fromCharCode\s*\(([^)]+)\)/g, (_, ns) => {
      try { return ns.split(',').map(n => String.fromCharCode(+n.trim())).join(''); } catch { return _; }
    });
    if (sfc !== code) { steps.push('String.fromCharCode'); code = sfc; }

    // Lua hex literals 0xFF → decimal (luaobfuscator.com uses 0xNN in string.char)
    const hexLit = code.replace(/\b(0x[0-9a-fA-F]+)\b/g, (_, h) => String(parseInt(h, 16)));
    if (hexLit !== code) { steps.push('Hex literals → decimal'); code = hexLit; }

    // Lua string.char(n,n,...) — handles decimal and hex (luaobfuscator.com, Lua Armor, etc.)
    const lsc = code.replace(/string\.char\s*\(([\d,\s\n\r]+)\)/gm, (_, ns) => {
      try {
        const nums = ns.split(',').map(n => parseInt(n.trim())).filter(n => !isNaN(n));
        if (nums.length >= 1 && nums.every(n => n >= 0 && n <= 255))
          return '"' + String.fromCharCode(...nums).replace(/\\/g,'\\\\').replace(/"/g,'\\"') + '"';
        return _;
      } catch { return _; }
    });
    if (lsc !== code) { steps.push('Lua string.char'); code = lsc; }

    // Lua decimal string escapes \DDD (triggered when 4+ sequences — clear obfuscation signal)
    const luaDecCount = (code.match(/\\[0-9]{1,3}/g) || []).length;
    if (luaDecCount >= 4) {
      const luaDec = code.replace(/\\([0-9]{1,3})/g, (_, n) => {
        const c = parseInt(n);
        return (c >= 32 && c <= 126) ? String.fromCharCode(c) : _;
      });
      if (luaDec !== code) { steps.push('Lua \\DDD decimal escapes'); code = luaDec; }
    }

    // table.concat({n,n,...}) byte array → string
    const tbl = code.replace(/table\.concat\s*\(\s*\{([\d,\s]+)\}\s*(?:,\s*["'].*?["'])?\s*\)/g, (_, ns) => {
      try {
        const nums = ns.split(',').map(n => parseInt(n.trim())).filter(n => !isNaN(n));
        if (nums.length >= 2 && nums.every(n => n > 0 && n <= 127))
          return '"' + String.fromCharCode(...nums) + '"';
        return _;
      } catch { return _; }
    });
    if (tbl !== code) { steps.push('table.concat byte array'); code = tbl; }

    // atob() inline calls
    const ab = code.replace(/\batob\s*\(['"`]([A-Za-z0-9+/=]+)['"`]\)/g,
      (_, b) => { try { return atob(b); } catch { return _; } });
    if (ab !== code) { steps.push('atob()'); code = ab; }

    // Prometheus-style: local T={"s1","s2",...}  expand T[1]→"s1"
    const ptMatch = code.match(/\blocal\s+(\w+)\s*=\s*\{(\s*"[^"]*"\s*(?:,\s*"[^"]*"\s*){4,})\}/);
    if (ptMatch) {
      try {
        const [, tName, tBody] = ptMatch;
        const entries = [...tBody.matchAll(/"([^"]*)"/g)].map(m => m[1]);
        if (entries.length >= 5) {
          const re = new RegExp(tName + '\\s*\\[\\s*(\\d+)\\s*\\]', 'g');
          const expanded = code.replace(re, (_, i) => {
            const val = entries[parseInt(i) - 1];
            return val !== undefined ? `"${val}"` : _;
          });
          if (expanded !== code) { steps.push('Prometheus string table'); code = expanded; }
        }
      } catch {}
    }

    // XOR-decrypted string.char: string.char(bit.bxor(n,key),...) — try constant key extraction
    const xorMatch = code.match(/string\.char\s*\(\s*(?:bit\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)[\s,]*){3,}\)/);
    if (xorMatch) {
      try {
        const xorNums = [...code.matchAll(/bit\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g)];
        if (xorNums.length >= 3) {
          const decoded = xorNums.map(m => String.fromCharCode(parseInt(m[1]) ^ parseInt(m[2]))).join('');
          if (/[\x20-\x7E]{4,}/.test(decoded)) {
            code = code.replace(/string\.char\s*\((?:\s*bit\.bxor\s*\(\s*\d+\s*,\s*\d+\s*\)\s*,?\s*)+\)/g, `"${decoded}"`);
            steps.push('XOR string.char decode');
          }
        }
      } catch {}
    }

    // obfuscator.io hex-array: build string table then inline references
    const hexArrM = code.match(/(_0x[0-9a-f]+)\s*=\s*\[([^\]]+)\]/i);
    if (hexArrM) {
      try {
        const [, arrName, body] = hexArrM;
        const entries = [...body.matchAll(/'([^']*)'/g)].map(m => m[1]);
        if (entries.length >= 3) {
          const escapedName = arrName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const re = new RegExp(escapedName + '\\s*\\(\\s*(\\d+)\\s*\\)', 'g');
          const exp = code.replace(re, (_, i) => {
            const v = entries[parseInt(i)]; return v !== undefined ? `"${v}"` : _;
          });
          if (exp !== code) { steps.push('obfuscator.io hex array'); code = exp; }
        }
      } catch {}
    }

    // Lua simple arithmetic constant folding: (3+4) → 7, useful after hex literal expand
    const arith = code.replace(/\(\s*(\d+)\s*([+\-*])\s*(\d+)\s*\)/g, (_, a, op, b) => {
      const va = parseInt(a), vb = parseInt(b);
      if (op === '+') return String(va + vb);
      if (op === '-') return String(va - vb);
      if (op === '*' && va * vb < 32768) return String(va * vb);
      return _;
    });
    if (arith !== code) { steps.push('Arithmetic folding'); code = arith; }

    // string.byte lookup table reverse: {[65]="A",[66]="B",...}[n] → char
    const sbTblRe = /\{([^}]{20,})\}\s*\[(\d+)\]/g;
    const sbDecoded = code.replace(sbTblRe, (whole, body, idx) => {
      try {
        const entry = body.match(new RegExp('\\[' + idx + '\\]\\s*=\\s*["\']([^"\']+)["\']'));
        return entry ? `"${entry[1]}"` : whole;
      } catch { return whole; }
    });
    if (sbDecoded !== code) { steps.push('Byte lookup table'); code = sbDecoded; }

    // Dean Edwards packer — flag it (can't safely eval but mark)
    if (pass === 0 && /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e/.test(code)) {
      steps.push('Dean Edwards Packer — requires eval to fully unpack (shown raw)');
    }

    // Base64 blob (pass 0 only)
    if (pass === 0 && /^[A-Za-z0-9+/]+=*$/.test(code.trim()) && code.trim().length > 20) {
      try { const d = atob(code.trim()); if (/[\x20-\x7E\n\r]{10,}/.test(d)) { steps.push('Base64 blob'); code = d; } } catch {}
    }

    // Hex blob (pass 0 only)
    if (pass === 0) {
      const stripped = code.replace(/[\s\n]/g, '');
      if (/^[0-9a-fA-F]+$/.test(stripped) && stripped.length > 20 && stripped.length % 2 === 0) {
        const d = stripped.match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('');
        if (/[\x20-\x7E]{10,}/.test(d)) { steps.push('Hex blob'); code = d; }
      }
    }

    if (code === prev) break;
  }

  const isVM = obfType && /VM|bytecode|Luraph|IronBrew|Moonsec/i.test(obfType);
  const vmStrings = isVM ? extractBytecodeStrings(input) : [];
  const lang  = detectLang(code);
  const risks = detectRisks(code);
  const out   = [];

  // ── Obfuscator banner ──
  if (obfType) {
    out.push('=== OBFUSCATOR IDENTIFIED ===');
    out.push(`Type:     ${obfType}`);
    if (isVM) {
      out.push('⚠️  VM-based: original Lua was compiled to bytecode, then encrypted.');
      out.push('   In-browser decode is partial — VM requires native Lua execution.');
      out.push('   Loader URLs and extracted strings are shown below.');
    }
    out.push('');
  }

  // ── Loaders / remote sources ──
  if (loaders.length) {
    out.push('=== LOADERS / REMOTE CODE SOURCES ===');
    loaders.forEach(l => out.push(l));
    out.push('');
  }

  // ── Strings extracted from VM bytecode ──
  if (vmStrings.length) {
    out.push(`=== STRINGS EXTRACTED FROM BYTECODE (${vmStrings.length}) ===`);
    vmStrings.forEach(s => out.push(`  "${s}"`));
    out.push('');
  }

  // ── Decode result ──
  if (steps.length) {
    out.push(`=== DECODED — ${steps.length} layer${steps.length > 1 ? 's' : ''} removed ===`);
    out.push(`Passes:   ${steps.join(' → ')}`);
    out.push(`Language: ${lang}`);
    out.push('');
    out.push(code);
  } else if (isVM && !steps.length) {
    out.push('=== RAW INPUT (VM-encrypted — not decodable in browser) ===');
    out.push(code.length > 1400 ? code.slice(0, 1400) + `\n\n... [${code.length - 1400} more chars truncated]` : code);
  } else if (!obfType && !loaders.length) {
    out.push('=== OUTPUT ===');
    out.push(`Language: ${lang}`);
    out.push('No encoding layers found. Code appears plain or uses unsupported custom crypto.');
    out.push('');
    out.push(code);
  }

  // ── Risks ──
  if (risks.length) {
    out.push('\n=== ⚠️ RISK INDICATORS ===');
    risks.forEach(r => out.push('  🚨 ' + r));
  } else if (steps.length || loaders.length) {
    out.push('\n✅ No dangerous patterns detected in output.');
  }

  setResult('deobfResult', out.join('\n'));
}

// Extract remote loader targets from code
function extractLoaders(code) {
  const results = [];
  let m;

  // game:HttpGet / HttpService:GetAsync / PostAsync
  const httpRe = /(?:game|HttpService|service)\s*[:.]\s*(?:HttpGet|GetAsync|PostAsync)\s*\(\s*["']([^"']+)["']/gi;
  while ((m = httpRe.exec(code)) !== null) results.push(`🌐 HttpGet URL: ${m[1]}`);

  // syn.request / http.request (exploit HTTP libraries)
  const synRe = /(?:syn|http|request|fluxus|krnl)\s*\.?\s*(?:request|GET|POST)\s*\(\s*\{[^}]*[Uu]rl\s*=\s*["']([^"']+)["']/gi;
  while ((m = synRe.exec(code)) !== null) results.push(`🔗 HTTP request URL: ${m[1]}`);

  // loadstring(...)()
  const lsRe = /(?:pcall\s*\(\s*)?loadstring\s*\(([^)]{1,500})\)\s*\)?\s*(?:\(\))?/g;
  while ((m = lsRe.exec(code)) !== null) {
    const src = m[1].trim();
    if (/^["']/.test(src)) results.push(`📜 loadstring literal: ${src.slice(0, 160)}`);
    else results.push(`📜 loadstring(${src.slice(0, 120)})`);
  }

  // require with Roblox asset ID
  const reqRe = /\brequire\s*\(\s*(\d{7,13})\s*\)/g;
  while ((m = reqRe.exec(code)) !== null) results.push(`📦 require() Roblox asset ID: ${m[1]}`);

  // dofile / loadfile
  const dfRe = /\b(dofile|loadfile)\s*\(\s*["']([^"']+)["']\)/gi;
  while ((m = dfRe.exec(code)) !== null) results.push(`📂 ${m[1]}: ${m[2]}`);

  // Raw https?:// strings not already captured
  const urlRe = /["'](https?:\/\/[^"'\s]{8,})["']/g;
  const seen = new Set(results.map(r => r));
  while ((m = urlRe.exec(code)) !== null) {
    if (!results.some(r => r.includes(m[1]))) results.push(`🔍 URL in code: ${m[1]}`);
  }

  return results;
}

// Extract readable strings from VM bytecode blob
function extractBytecodeStrings(code) {
  const found = new Set();
  let m;

  // Decode long string literals (bytecode stored as escaped string)
  const longRe = /["']([^"']{60,})["']/g;
  while ((m = longRe.exec(code)) !== null) {
    let raw = m[1];
    raw = raw.replace(/\\([0-9]{1,3})/g, (_, n) => {
      const c = parseInt(n);
      return (c >= 32 && c <= 126) ? String.fromCharCode(c) : '\x00';
    });
    const runs = raw.match(/[\x20-\x7E]{5,}/g) || [];
    runs.forEach(r => { if (/[a-zA-Z]{3}/.test(r) && r.length < 200) found.add(r.trim()); });
  }

  // Short visible string literals
  const shortRe = /["']([a-zA-Z_][\w./: -]{3,80})["']/g;
  while ((m = shortRe.exec(code)) !== null) found.add(m[1]);

  // Filter Lua/VM boilerplate keywords
  const noise = new Set(['local','function','return','end','then','else','true','false','nil','and','or','not','repeat','until','for','while','do','break','in']);
  return [...found].filter(s => !noise.has(s) && s.length > 3).slice(0, 45);
}

function detectObfuscator(code) {
  // Named comments / string markers
  if (/Luraph/i.test(code))                                   return 'Luraph (Lua VM obfuscator)';
  if (/IronBrew/i.test(code))                                  return 'IronBrew 2 (Lua VM obfuscator)';
  if (/Moonsec/i.test(code))                                   return 'Moonsec (Lua VM obfuscator)';
  if (/Prometheus/i.test(code))                                return 'Prometheus (Lua string-table obfuscator)';
  if (/LuaSeel|Lua\s*Seel/i.test(code))                      return 'LuaSeel (Lua obfuscator)';
  if (/LuaArmor|Lua\s*Armor/i.test(code))                    return 'Lua Armor (string.char obfuscator)';
  if (/Synapse\s*Xen|SynXen/i.test(code))                   return 'Synapse Xen (VM-based exploit obfuscator)';
  if (/Comet\s*Obf/i.test(code))                             return 'Comet obfuscator';
  if (/ByteCode|Bytecode\s*VM/i.test(code))                  return 'Generic Lua Bytecode VM';
  if (/luaobfuscator\.com/i.test(code))                      return 'luaobfuscator.com';
  if (/obfuscated by obfuscator\.io/i.test(code))            return 'obfuscator.io (JS)';

  // luaobfuscator.com structural fingerprint:
  // - single-letter locals everywhere + 0xNN hex char codes + no comments
  const hexCharCount = (code.match(/0x[0-9a-fA-F]{2}\b/g) || []).length;
  const singleLetterLocals = (code.match(/\blocal\s+[a-z]\s*=/g) || []).length;
  if (hexCharCount > 10 && singleLetterLocals > 5) return 'luaobfuscator.com (hex char encoding)';

  // luaobfuscator.com VM level: repeated function/table pattern with math ops
  if (/math\.(floor|random|huge)/.test(code) && hexCharCount > 5 && /string\.char/.test(code)) return 'luaobfuscator.com (VM level — hex + math obfuscation)';

  // Luraph / Moonsec structural: long bytecode string + bit library ops
  if (/^local\s+\w\s*=\s*["'][^"']{300,}["']/.test(code) && /bit\.(b?xor|band|bor|rshift|lshift)/.test(code)) {
    if (/\[0\]\s*=/.test(code)) return 'Moonsec v3 (VM — 0-indexed opcode dispatch)';
    if (/\[1\]\s*=\s*function/.test(code)) return 'Moonsec v2 (VM)';
    return 'Luraph / IronBrew (VM — encrypted Lua bytecode)';
  }

  // IronBrew: getfenv + large opcode table
  if (/local\s+\w+\s*=\s*\{[^}]{500,}\}/.test(code) && /getfenv|setfenv/.test(code)) return 'IronBrew (Lua VM)';

  // Generic VM: large table + load
  if (/local\s+\w+\s*=\s*\{[^}]{800,}\}/.test(code) && /\b(?:loadstring|load)\s*\(/.test(code)) return 'Custom Lua VM obfuscator';

  // Lua Armor: many string.char chains
  if (/(string\.char\s*\([\d,\s]{30,}\)[\s.]*){2,}/.test(code)) return 'Lua Armor (string.char chain)';

  // Prometheus: string table at top
  if (/^local\s+\w+\s*=\s*\{\s*"[^"]+"\s*(?:,\s*"[^"]+"\s*){4,}\}/m.test(code)) return 'Prometheus (string table)';

  // Heavy \DDD decimal encoding
  if ((code.match(/\\[0-9]{1,3}/g) || []).length > 30) return 'Lua decimal-escape obfuscator';

  // JS obfuscators
  if (/_0x[0-9a-f]{4,}\s*=\s*\[/.test(code))           return 'obfuscator.io / js-obfuscator (hex array)';
  if (/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e/.test(code)) return 'Dean Edwards Packer (JS)';
  if (/\['\\x[0-9a-f]{2}'\]/.test(code) && /eval/.test(code)) return 'JS string-escape obfuscator';

  return null;
}

function detectRisks(code) {
  const r = [];
  if (/\beval\s*\(/.test(code))                          r.push('eval() — arbitrary code execution');
  if (/\bFunction\s*\(/.test(code))                      r.push('Function() constructor — code execution');
  if (/document\.write/.test(code))                      r.push('document.write — DOM injection');
  if (/innerHTML\s*=/.test(code))                        r.push('innerHTML assignment — XSS risk');
  if (/\bfetch\s*\(|XMLHttpRequest/.test(code))          r.push('Network request — possible data exfiltration');
  if (/localStorage|sessionStorage/.test(code))          r.push('Storage access — credential/token theft');
  if (/document\.cookie/.test(code))                     r.push('Cookie access — session hijacking');
  if (/\bloadstring\s*\(/.test(code))                    r.push('loadstring — remote Lua script execution');
  if (/game:HttpGet|HttpService/.test(code))             r.push('Roblox HttpService — remote code loading');
  if (/getfenv|setfenv/.test(code))                      r.push('Lua getfenv/setfenv — sandbox escape');
  if (/getrawmetatable|setrawmetatable/.test(code))      r.push('getrawmetatable — hook/bypass attempt');
  if (/os\.execute|subprocess|popen/.test(code))         r.push('System command execution');
  if (/import\s+os|import\s+subprocess/.test(code))      r.push('Python OS module — system access');
  if (/powershell|cmd\.exe|wscript/i.test(code))         r.push('Shell execution detected');
  if (/bit\.b?xor/.test(code))                           r.push('Bitwise XOR ops — runtime decryption layer present');
  if (/discord\.com\/api\/webhooks/i.test(code))         r.push('Discord webhook — likely token/data exfiltration');
  if (/\btoken\b.*\bsend\b|\bHeaders\b.*\bAuthorization\b/i.test(code)) r.push('Auth token in HTTP header — credential exfil');
  if (/debug\.getinfo|debug\.getupvalue/i.test(code))   r.push('Lua debug lib — introspection/hook bypass');
  return r;
}

function detectLang(code) {
  if (/\blocal\s+\w+|string\.char|game\b|workspace\b|script\b|loadstring|\.new\s*\(/.test(code)) return 'Luau (Roblox)';
  if (/function\s*\w*\s*\(|const\s+|let\s+|var\s+|=>\s*\{|document\.|window\./.test(code))       return 'JavaScript';
  if (/def\s+\w+\s*\(|import\s+\w+|print\s*\(|__name__|:\s*$/.test(code))                        return 'Python';
  if (/\$\w+\s*=|Write-Host|Get-Process|Invoke-/i.test(code))                                     return 'PowerShell';
  if (/@echo\s|^REM\s|SET\s+\w+=|GOTO\s/im.test(code))                                            return 'Batch/CMD';
  if (/<html|<script|<!DOCTYPE/i.test(code))                                                        return 'HTML';
  if (/\bSELECT\b.*\bFROM\b|\bINSERT\b.*\bINTO\b/i.test(code))                                   return 'SQL';
  return 'Unknown / Generic';
}

// ===== FILE ANALYZER =====
function handleFileDrop(e) {
  e.preventDefault();
  document.getElementById('fileDrop').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) { document.getElementById('fileInput').files; analyzeFileObj(file); }
}

function analyzeFile() {
  const f = document.getElementById('fileInput').files[0];
  if (f) analyzeFileObj(f);
}

async function analyzeFileObj(file) {
  setResult('fileResult', 'Analyzing file...', 'loading');
  const out = [];
  out.push('=== FILE METADATA ===');
  out.push(`Name:          ${file.name}`);
  out.push(`Size:          ${(file.size/1024).toFixed(2)} KB (${file.size.toLocaleString()} bytes)`);
  out.push(`MIME Type:     ${file.type || 'Unknown'}`);
  out.push(`Last Modified: ${new Date(file.lastModified).toUTCString()}`);
  const ext = file.name.split('.').pop().toLowerCase();
  out.push(`Extension:     .${ext}`);
  const headerBuf = await file.slice(0,16).arrayBuffer();
  const headerBytes = new Uint8Array(headerBuf);
  out.push(`Magic Bytes:   ${Array.from(headerBytes).map(b=>b.toString(16).padStart(2,'0').toUpperCase()).join(' ')}`);
  const trueType = identifyMagicBytes(headerBytes);
  out.push(`True Type:     ${trueType}`);
  const mismatch = checkExtMismatch(ext, trueType);
  out.push(mismatch ? `🚨 MISMATCH: .${ext} extension but detected as ${trueType}` : '✅ Extension matches detected file type');
  out.push('\n=== HASHES ===');
  const buf = await file.arrayBuffer();
  for (const algo of ['SHA-1','SHA-256','SHA-512']) {
    const h = await crypto.subtle.digest(algo, buf);
    out.push(`${algo.padEnd(8)}: ${Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('')}`);
  }
  const textExts = ['js','html','htm','php','py','lua','bat','ps1','sh','cmd','vbs','json','xml','csv','txt','ts'];
  if (file.type.startsWith('text/') || textExts.includes(ext)) {
    const text = await file.text();
    out.push('\n=== CONTENT ANALYSIS ===');
    out.push(`Characters:    ${text.length.toLocaleString()}`);
    out.push(`Lines:         ${text.split('\n').length.toLocaleString()}`);
    const pats = [
      { name: 'eval/exec',         re: /eval\s*\(|exec\s*\(/i },
      { name: 'Base64 blob',       re: /[A-Za-z0-9+/]{60,}={0,2}/ },
      { name: 'Shell command',     re: /os\.system|subprocess|popen|Shell\(|cmd\.exe/i },
      { name: 'Network request',   re: /fetch\s*\(|XMLHttpRequest|HttpGet|urllib|requests\./i },
      { name: 'SQL pattern',       re: /SELECT.+FROM|INSERT\s+INTO|DROP\s+TABLE/i },
      { name: 'Credential string', re: /password\s*=|passwd|secret|api.?key|auth.?token/i },
      { name: 'XSS pattern',       re: /<script|javascript:|onerror\s*=/i },
      { name: 'Luau exploit',      re: /loadstring|getfenv|setfenv|HttpGet/i },
      { name: 'Hardcoded IP/URL',  re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|https?:\/\//i },
    ];
    const hits = pats.filter(p => p.re.test(text));
    if (hits.length) { out.push(`⚠️  ${hits.length} suspicious pattern(s):`); hits.forEach(h => out.push(`  🚨 ${h.name}`)); }
    else out.push('✅ No suspicious patterns in content.');
  }
  out.push('\n=== VERDICT ===');
  const dangerous = ['exe','bat','cmd','ps1','vbs','wsf','msi','scr','pif','hta','jar','sh'];
  if (dangerous.includes(ext))  out.push(`🚨 HIGH RISK — .${ext} is executable`);
  else if (mismatch)             out.push('🚨 HIGH RISK — Extension/content mismatch');
  else                           out.push('✅ No critical file-type threats detected');
  setResult('fileResult', out.join('\n'));
}

function identifyMagicBytes(b) {
  if (b[0]===0x25&&b[1]===0x50&&b[2]===0x44&&b[3]===0x46) return 'PDF document';
  if (b[0]===0x50&&b[1]===0x4B&&b[2]===0x03&&b[3]===0x04) return 'ZIP / DOCX / XLSX / APK / JAR';
  if (b[0]===0x89&&b[1]===0x50&&b[2]===0x4E&&b[3]===0x47) return 'PNG image';
  if (b[0]===0xFF&&b[1]===0xD8&&b[2]===0xFF)               return 'JPEG image';
  if (b[0]===0x47&&b[1]===0x49&&b[2]===0x46)               return 'GIF image';
  if (b[0]===0x4D&&b[1]===0x5A)                             return 'Windows PE Executable (EXE/DLL)';
  if (b[0]===0x7F&&b[1]===0x45&&b[2]===0x4C&&b[3]===0x46) return 'ELF Executable (Linux/Android)';
  if (b[0]===0xD0&&b[1]===0xCF&&b[2]===0x11&&b[3]===0xE0) return 'MS Office (DOC/XLS/PPT)';
  if (b[0]===0x52&&b[1]===0x61&&b[2]===0x72&&b[3]===0x21) return 'RAR archive';
  if (b[0]===0x37&&b[1]===0x7A&&b[2]===0xBC&&b[3]===0xAF) return '7-Zip archive';
  if (b[0]===0x1F&&b[1]===0x8B)                             return 'Gzip archive';
  if (b[0]===0xFF&&b[1]===0xFB||b[0]===0x49&&b[1]===0x44&&b[2]===0x33) return 'MP3 audio';
  if (b[4]===0x66&&b[5]===0x74&&b[6]===0x79&&b[7]===0x70) return 'MP4/MOV video';
  if (b[0]===0xCA&&b[1]===0xFE&&b[2]===0xBA&&b[3]===0xBE) return 'Java Class (bytecode)';
  return 'Unknown / Text-based';
}

function checkExtMismatch(ext, trueType) {
  if (trueType === 'Unknown / Text-based') return false;
  const map = { pdf:'PDF',png:'PNG',jpg:'JPEG',jpeg:'JPEG',gif:'GIF',exe:'Windows PE',dll:'Windows PE',zip:'ZIP',docx:'ZIP',xlsx:'ZIP',apk:'ZIP',jar:'ZIP',rar:'RAR','7z':'7-Zip',gz:'Gzip',mp3:'MP3',mp4:'MP4' };
  const expected = map[ext];
  if (!expected) return false;
  return !trueType.toLowerCase().includes(expected.toLowerCase());
}

// ===== IP FINGERPRINT / LOGGER =====
async function runFingerprint() {
  setResult('fingerprintResult', 'Collecting fingerprint data...', 'loading');
  const out = [];
  out.push('=== BROWSER / DEVICE ===');
  out.push(`User Agent:    ${navigator.userAgent}`);
  out.push(`Platform:      ${navigator.platform}`);
  out.push(`Language:      ${navigator.language}`);
  out.push(`Languages:     ${(navigator.languages || []).join(', ') || 'N/A'}`);
  out.push(`Screen:        ${screen.width}×${screen.height} (${screen.colorDepth}bpp)`);
  out.push(`Device Pixel:  ${window.devicePixelRatio}x`);
  out.push(`Viewport:      ${window.innerWidth}×${window.innerHeight}`);
  out.push(`Timezone:      ${Intl.DateTimeFormat().resolvedOptions().timeZone}`);
  out.push(`TZ Offset:     UTC${-new Date().getTimezoneOffset()/60 >= 0 ? '+' : ''}${-new Date().getTimezoneOffset()/60}`);
  if (navigator.hardwareConcurrency) out.push(`CPU Cores:     ${navigator.hardwareConcurrency}`);
  if (navigator.deviceMemory)        out.push(`RAM:           ~${navigator.deviceMemory} GB`);
  if (navigator.connection)          out.push(`Connection:    ${navigator.connection.effectiveType || 'N/A'} / ${navigator.connection.downlink || '?'} Mbps`);
  out.push(`Cookies:       ${navigator.cookieEnabled ? 'Enabled' : 'Disabled'}`);
  out.push(`DNT:           ${navigator.doNotTrack === '1' ? 'Enabled' : 'Not set'}`);
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (ext) { out.push(`GPU Vendor:    ${gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)}`); out.push(`GPU Renderer:  ${gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)}`); }
    }
  } catch {}
  out.push('\n=== IP / LOCATION ===');
  try {
    const res = await fetch('https://ipinfo.io/json');
    const d = await res.json();
    out.push(`Public IP:     ${d.ip}`);
    out.push(`Hostname:      ${d.hostname || 'N/A'}`);
    out.push(`City:          ${d.city || 'N/A'}`);
    out.push(`Region:        ${d.region || 'N/A'}`);
    out.push(`Country:       ${d.country || 'N/A'}`);
    out.push(`ISP/Org:       ${d.org || 'N/A'}`);
    out.push(`Coordinates:   ${d.loc || 'N/A'}`);
  } catch { out.push('IP lookup failed.'); }
  out.push('\n=== ⚠️ WHAT AN IP LOGGER COLLECTS ===');
  out.push('All data above is passively collected when you visit any page.');
  out.push('No clicks or downloads required — just loading the URL is enough.');
  out.push('IP loggers also capture: referrer URL, timestamp, unique visit ID.');
  out.push('This tool exists to educate — know what you expose before clicking.');
  setResult('fingerprintResult', out.join('\n'));
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
