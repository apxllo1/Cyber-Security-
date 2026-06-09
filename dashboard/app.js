// Dashboard Application Logic
const API_URL = localStorage.getItem('apiUrl') || 'http://localhost:3001/api';
const BOT_TOKEN = localStorage.getItem('botToken') || '';
let commandHistory = JSON.parse(localStorage.getItem('commandHistory')) || [];

// ===== PAGE NAVIGATION =====
document.querySelectorAll('.dash-nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const page = btn.dataset.page;
    
    document.querySelectorAll('.dash-nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.dash-page').forEach(p => p.classList.remove('active'));
    
    btn.classList.add('active');
    document.getElementById(`page-${page}`).classList.add('active');

    if (page === 'home') loadStatus();
    if (page === 'history') loadHistory();
  });
});

// ===== TOOL SWITCHING =====
function switchTool(toolName) {
  document.querySelectorAll('.tool-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  
  document.getElementById(`tool-${toolName}`).classList.add('active');
  event.target.classList.add('active');
}

// ===== API CALLS =====
async function apiCall(endpoint, data) {
  try {
    const response = await fetch(`${API_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${BOT_TOKEN}`
      },
      body: JSON.stringify(data)
    });
    return await response.json();
  } catch (error) {
    console.error('API Error:', error);
    return { error: error.message };
  }
}

async function apiGet(endpoint) {
  try {
    const response = await fetch(`${API_URL}${endpoint}`, {
      headers: { 'Authorization': `Bearer ${BOT_TOKEN}` }
    });
    return await response.json();
  } catch (error) {
    console.error('API Error:', error);
    return { error: error.message };
  }
}

// ===== STATUS PAGE =====
async function loadStatus() {
  const res = await apiGet('/bot/status');
  
  if (!res.error) {
    document.getElementById('botStatus').textContent = '🟢 Online';
    document.getElementById('activeConns').textContent = res.activeConnections || '0';
    document.getElementById('commandsToday').textContent = commandHistory.length;
    document.getElementById('uptime').textContent = formatUptime(res.uptime);
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
  } else {
    document.getElementById('botStatus').textContent = '🔴 Offline';
  }

  loadActivityLog();
}

function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

function loadActivityLog() {
  const log = document.getElementById('activityLog');
  const recent = commandHistory.slice(-5).reverse();

  if (recent.length === 0) {
    log.innerHTML = '<p>No recent activity</p>';
    return;
  }

  log.innerHTML = recent.map(entry => `
    <div class="log-entry">
      <span class="log-time">${entry.time}</span> - 
      <span>${entry.command}</span>
    </div>
  `).join('');
}

function executeCommand(cmd) {
  addToHistory(cmd, 'Command executed');
  console.log(`Executed: ${cmd}`);
}

// ===== TOOL FUNCTIONS =====
async function toolHash(algo) {
  const text = document.getElementById('hashInput').value;
  if (!text) return alert('Enter text first');

  const res = await apiCall('/hash', { text, algo });
  document.getElementById('hashResult').textContent = res.hash || 'Error';
  addToHistory(`hash ${algo}`, res.hash);
}

async function toolB64(action) {
  const text = document.getElementById('b64Input').value;
  if (!text) return alert('Enter text first');

  const res = await apiCall('/b64', { text, action });
  document.getElementById('b64Result').textContent = res.result || 'Error';
  addToHistory(`b64 ${action}`, res.result);
}

async function toolIP() {
  const ip = document.getElementById('ipInput').value || 'auto';

  const res = await apiCall('/ip', { ip });
  const output = res.ip ? `IP: ${res.ip}\nCity: ${res.city}\nCountry: ${res.country}\nISP: ${res.org}` : 'Error';
  document.getElementById('ipResult').textContent = output;
  addToHistory(`ip ${ip}`, output);
}

async function toolJWT() {
  const token = document.getElementById('jwtInput').value;
  if (!token) return alert('Enter JWT first');

  const res = await apiCall('/jwt', { token });
  const output = res.header ? `Algorithm: ${res.header.alg}\nExpired: ${res.expired ? 'Yes' : 'No'}` : 'Error';
  document.getElementById('jwtResult').textContent = output;
  addToHistory('jwt analyze', output);
}

async function toolURL() {
  const url = document.getElementById('urlInput').value;
  if (!url) return alert('Enter URL first');

  const res = await apiCall('/url', { url });
  const output = res.domain ? `Domain: ${res.domain}\nRisk: ${res.riskLevel}\nFlags: ${res.flags.join(', ')}` : 'Error';
  document.getElementById('urlResult').textContent = output;
  addToHistory(`url analyze`, output);
}

async function toolScan() {
  const input = document.getElementById('scanInput').value;
  if (!input) return alert('Enter text first');

  const res = await apiCall('/scan', { input });
  const output = `Patterns: ${res.patterns.join(', ')}\nRisk: ${res.risk}`;
  document.getElementById('scanResult').textContent = output;
  addToHistory('scan', output);
}

// ===== HISTORY =====
function addToHistory(command, result) {
  const entry = {
    command,
    result: result.slice(0, 100),
    time: new Date().toLocaleTimeString()
  };

  commandHistory.push(entry);
  localStorage.setItem('commandHistory', JSON.stringify(commandHistory));
  loadActivityLog();
}

function loadHistory() {
  const list = document.getElementById('historyList');

  if (commandHistory.length === 0) {
    list.innerHTML = '<p>No history</p>';
    return;
  }

  list.innerHTML = commandHistory.reverse().map(entry => `
    <div class="history-item">
      <div class="history-time">${entry.time}</div>
      <div class="history-cmd">${entry.command}</div>
      <div class="history-result">${entry.result}</div>
    </div>
  `).join('');
}

function filterHistory() {
  const filter = document.getElementById('historyFilter').value.toLowerCase();
  const items = document.querySelectorAll('.history-item');

  items.forEach(item => {
    const text = item.textContent.toLowerCase();
    item.style.display = text.includes(filter) ? 'block' : 'none';
  });
}

function clearHistory() {
  if (confirm('Clear all history?')) {
    commandHistory = [];
    localStorage.removeItem('commandHistory');
    loadHistory();
  }
}

// ===== SETTINGS =====
function toggleDarkMode() {
  document.body.classList.toggle('light-mode');
  localStorage.setItem('darkMode', document.body.classList.contains('light-mode'));
}

function saveSettings() {
  const apiUrl = document.getElementById('apiUrl').value;
  if (apiUrl) localStorage.setItem('apiUrl', apiUrl);
  alert('Settings saved!');
}

function logout() {
  if (confirm('Logout?')) {
    localStorage.removeItem('botToken');
    window.location.href = 'login.html';
  }
}

// ===== INIT =====
window.addEventListener('load', () => {
  if (!BOT_TOKEN) {
    window.location.href = 'login.html';
  }
  loadStatus();
});

// Auto-refresh status every 5 seconds
setInterval(loadStatus, 5000);
