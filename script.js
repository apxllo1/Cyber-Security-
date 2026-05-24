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
  try { url = new URL(raw); } catch { setResult('urlResult', 'Invalid URL format.', 'err'); return; }
  const domain = url.hostname;
  const out = [];
  out.push('=== URL STRUCTURE ===');
  out.push(`Protocol:  ${url.protocol}`);
  out.push(`Domain:    ${domain}`);
  if (url.port)              out.push(`Port:      ${url.port}`);
  if (url.pathname !== '/')  out.push(`Path:      ${url.pathname}`);
  if (url.search)            out.push(`Params:    ${url.search}`);
  if (url.hash)              out.push(`Fragment:  ${url.hash}`);
  out.push('\n=== SECURITY CHECKS ===');
  const flags = [], safe = [];
  if (url.protocol === 'https:') safe.push('✅ HTTPS — encrypted connection');
  else flags.push('⚠️  HTTP — unencrypted, vulnerable to MITM');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) flags.push('🚨 Raw IP used as domain — real identity hidden');
  const shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','adf.ly','v.gd','tr.im','rb.gy','cutt.ly'];
  if (shorteners.some(s => domain === s || domain.endsWith('.' + s))) flags.push('⚠️  URL shortener — true destination concealed');
  if (domain.includes('xn--')) flags.push('🚨 Punycode domain — possible homograph/lookalike attack');
  const parts = domain.split('.');
  if (parts.length > 4) flags.push(`⚠️  ${parts.length - 2} subdomains — may obscure the real domain`);
  const brands = ['paypal','amazon','google','microsoft','apple','netflix','facebook','roblox','discord','steam','bank','secure','login','verify','update','account'];
  const found = brands.filter(b => domain.toLowerCase().includes(b));
  if (found.length) flags.push(`⚠️  Brand keywords in domain: ${found.join(', ')} — possible phishing`);
  const dangerExt = ['.exe','.bat','.cmd','.ps1','.vbs','.wsf','.msi','.scr','.pif','.hta','.jar','.sh'];
  if (dangerExt.some(e => url.pathname.toLowerCase().endsWith(e))) flags.push(`🚨 Dangerous file extension in path`);
  if (/\.(pdf|doc|docx|jpg|png)\.(exe|bat|cmd|ps1|scr)/i.test(url.pathname)) flags.push('🚨 Double extension trick — disguised executable');
  if (/%00|%0d|%0a/i.test(url.pathname)) flags.push('🚨 Null byte / CRLF injection in URL');
  const redirectParams = ['redirect','url','goto','next','return','returnurl','callback','destination'];
  const foundParams = [];
  for (const [k] of url.searchParams) if (redirectParams.some(r => k.toLowerCase().includes(r))) foundParams.push(k);
  if (foundParams.length) flags.push(`⚠️  Open redirect param(s): ${foundParams.join(', ')}`);
  for (const [k, v] of url.searchParams) {
    if (v.length > 16 && /^[A-Za-z0-9+/]+=*$/.test(v)) {
      try { const d = atob(v); if (/[a-zA-Z]{5,}/.test(d)) flags.push(`⚠️  Base64 in param "${k}" → ${d.slice(0,80)}`); } catch {}
    }
  }
  flags.forEach(f => out.push(f));
  safe.forEach(s => out.push(s));
  if (!flags.length && !safe.length) out.push('✅ No suspicious patterns detected');
  out.push('\n=== DNS / IP INFO ===');
  try {
    const dns = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=A`, { headers: { Accept: 'application/dns-json' } });
    const dnsData = await dns.json();
    const ips = dnsData.Answer?.map(r => r.data).filter(d => /^\d/.test(d)) || [];
    if (ips.length) {
      out.push(`DNS (A):   ${ips.join(', ')}`);
      const ip = await fetch(`https://ipinfo.io/${ips[0]}/json`);
      const ipData = await ip.json();
      if (!ipData.bogon) {
        out.push(`Location:  ${ipData.city || '?'}, ${ipData.region || '?'}, ${ipData.country || '?'}`);
        out.push(`ISP/Org:   ${ipData.org || 'N/A'}`);
        out.push(`Timezone:  ${ipData.timezone || 'N/A'}`);
      }
    } else out.push('No A records found.');
  } catch { out.push('DNS lookup failed.'); }
  out.push('\n=== VERDICT ===');
  const crit = flags.filter(f => f.startsWith('🚨')).length;
  const warn = flags.filter(f => f.startsWith('⚠️')).length;
  if (crit)        out.push(`🚨 HIGH RISK — ${crit} critical issue(s) detected`);
  else if (warn>1) out.push(`⚠️  SUSPICIOUS — ${warn} warnings — investigate before sharing`);
  else if (warn)   out.push('⚠️  LOW CONCERN — 1 minor flag — verify before trusting');
  else             out.push('✅ APPEARS SAFE — No significant threats found');
  setResult('urlResult', out.join('\n'));
}

// ===== CODE DEOBFUSCATOR =====
function deobfuscate() {
  const input = document.getElementById('deobfInput').value.trim();
  if (!input) { setResult('deobfResult', 'Paste obfuscated code above.', 'warn'); return; }
  let code = input;
  const steps = [];
  for (let pass = 0; pass < 8; pass++) {
    const prev = code;
    try { const d = decodeURIComponent(code); if (d !== code) { steps.push('URL decode'); code = d; } } catch {}
    const ent = code.replace(/&#(\d+);/g,(_,n)=>String.fromCharCode(+n)).replace(/&#x([0-9a-fA-F]+);/g,(_,h)=>String.fromCharCode(parseInt(h,16))).replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"');
    if (ent !== code) { steps.push('HTML entity decode'); code = ent; }
    const uni = code.replace(/\\u([0-9a-fA-F]{4})/g,(_,h)=>String.fromCharCode(parseInt(h,16)));
    if (uni !== code) { steps.push('Unicode \\uXXXX'); code = uni; }
    const hex = code.replace(/\\x([0-9a-fA-F]{2})/g,(_,h)=>String.fromCharCode(parseInt(h,16)));
    if (hex !== code) { steps.push('Hex \\xXX'); code = hex; }
    const sfc = code.replace(/String\.fromCharCode\s*\(([^)]+)\)/g,(_,ns)=>{try{return ns.split(',').map(n=>String.fromCharCode(+n.trim())).join('');}catch{return _;}});
    if (sfc !== code) { steps.push('String.fromCharCode'); code = sfc; }
    const ab = code.replace(/atob\s*\(['"`]([A-Za-z0-9+/=]+)['"`]\)/g,(_,b)=>{try{return atob(b);}catch{return _;}});
    if (ab !== code) { steps.push('atob() Base64'); code = ab; }
    if (pass === 0 && /^[A-Za-z0-9+/]+=*$/.test(code) && code.length > 20) {
      try { const d = atob(code); if (/[\x20-\x7E\n\r]{10,}/.test(d)) { steps.push('Base64 blob'); code = d; } } catch {}
    }
    if (pass === 0 && /^[0-9a-fA-F\s]+$/.test(code) && code.replace(/\s/g,'').length > 20 && code.replace(/\s/g,'').length % 2 === 0) {
      const hc = code.replace(/\s/g,'');
      const d = hc.match(/.{2}/g)?.map(h=>String.fromCharCode(parseInt(h,16))).join('') || '';
      if (/[\x20-\x7E]{10,}/.test(d)) { steps.push('Hex blob'); code = d; }
    }
    if (code === prev) break;
  }
  const lang = detectLang(code);
  const risks = [];
  if (/eval\s*\(/.test(code))                    risks.push('eval() — arbitrary code execution');
  if (/Function\s*\(/.test(code))                risks.push('Function() constructor — code execution');
  if (/document\.write/.test(code))              risks.push('document.write — DOM injection');
  if (/innerHTML\s*=/.test(code))                risks.push('innerHTML — XSS risk');
  if (/fetch\s*\(|XMLHttpRequest/.test(code))    risks.push('Network request — possible data exfiltration');
  if (/localStorage|sessionStorage/.test(code))  risks.push('Storage access — credential/token theft');
  if (/document\.cookie/.test(code))             risks.push('Cookie access — session hijacking');
  if (/loadstring/.test(code))                   risks.push('Luau loadstring — remote script execution');
  if (/game:HttpGet|HttpService/.test(code))     risks.push('Roblox HttpService — remote code loading');
  if (/os\.execute|subprocess|popen/.test(code)) risks.push('System command execution');
  if (/import\s+os|import\s+subprocess/.test(code)) risks.push('Python OS access — system commands');
  if (/powershell|cmd\.exe|wscript/i.test(code)) risks.push('Shell execution detected');
  let out = steps.length
    ? `=== DECODED (${steps.length} layer${steps.length>1?'s':''}) ===\nLayers:   ${steps.join(' → ')}\nLanguage: ${lang}\n\n`
    : `=== NO ENCODING DETECTED ===\nLanguage: ${lang}\nInput appears already decoded or uses unknown encoding.\n\n`;
  out += '=== OUTPUT ===\n' + code;
  out += risks.length ? '\n\n=== ⚠️ RISK INDICATORS ===\n' + risks.map(r => '  🚨 ' + r).join('\n') : steps.length ? '\n\n✅ No dangerous patterns detected in decoded output.' : '';
  setResult('deobfResult', out);
}

function detectLang(code) {
  if (/function\s*\w*\s*\(|const\s+|let\s+|var\s+|=>\s*\{|document\.|window\./.test(code)) return 'JavaScript';
  if (/def\s+\w+\s*\(|import\s+\w+|print\s*\(|__name__|:\s*$/.test(code))                  return 'Python';
  if (/local\s+\w+|function\s+\w+\(|loadstring|game\.|workspace\.|script\./.test(code))    return 'Luau (Roblox)';
  if (/\$\w+\s*=|Write-Host|Get-Process|Invoke-|\.ps1/.test(code))                         return 'PowerShell';
  if (/@echo\s|^REM\s|SET\s+\w+=|GOTO\s/im.test(code))                                     return 'Batch/CMD';
  if (/<html|<script|<!DOCTYPE/i.test(code))                                                 return 'HTML';
  if (/\bSELECT\b.*\bFROM\b|\bINSERT\b.*\bINTO\b/i.test(code))                            return 'SQL';
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
