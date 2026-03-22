/**
 * Basilisk Desktop — Core Module
 * Window controls, shared state, navigation, helpers, backend connection, WebSocket.
 */

// ── Window controls ──
document.getElementById('btn-min')?.addEventListener('click', () => (window.basilisk?.send || window.api?.send)?.('window:minimize'));
document.getElementById('btn-max')?.addEventListener('click', () => (window.basilisk?.send || window.api?.send)?.('window:maximize'));
document.getElementById('btn-close')?.addEventListener('click', () => (window.basilisk?.send || window.api?.send)?.('window:close'));

// ── Shared State (global) ──
const BRIDGE = 'http://127.0.0.1:8741';
let currentSession = null;
let allFindings = [];
let scanning = false;
let timerInterval = null;
let timerStart = null;
let authToken = null;

// ── Navigation ──
const tabs = document.querySelectorAll('.tab');
const views = document.querySelectorAll('.view');

tabs.forEach(t => {
    t.addEventListener('click', () => {
        tabs.forEach(x => x.classList.remove('active'));
        views.forEach(x => x.classList.remove('active'));
        t.classList.add('active');
        const v = document.getElementById(`v-${t.dataset.v}`);
        if (v) v.classList.add('active');
        // lazy load
        if (t.dataset.v === 'modules') { loadModules(); loadMultiturnModules(); }
        if (t.dataset.v === 'evolution') loadEvolutionOperators();
        if (t.dataset.v === 'sessions' || t.dataset.v === 'reports') loadSessions();
        if (t.dataset.v === 'settings') loadNative();
    });
});

// ── Helpers ──
const esc = s => { const d = document.createElement('div'); d.innerText = s || ''; return d.innerHTML; };
const trunc = (s, n = 100) => { const x = typeof s === 'string' ? s : JSON.stringify(s || ''); return x.length > n ? x.slice(0, n) + '…' : x; };
const ts = () => new Date().toLocaleTimeString('en-US', { hour12: false });

function log(type, msg) {
    [document.getElementById('sys-log'), document.getElementById('full-log')].forEach(el => {
        if (!el) return;
        const d = document.createElement('div');
        d.className = `ll ${type}`;
        d.innerText = `[${ts()}] ${msg}`;
        el.appendChild(d);
        el.scrollTop = el.scrollHeight;
    });
    if (type === 'err') toast('error', msg);
}

function toast(type, msg) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    const iconMap = { error: '✕', ok: '✓', inf: 'ℹ' };
    const icon = iconMap[type] || '•';
    t.innerHTML = `
        <div class="toast-icon">${icon}</div>
        <div class="toast-msg">${esc(msg)}</div>
    `;
    container.appendChild(t);
    setTimeout(() => {
        t.classList.add('removing');
        setTimeout(() => t.remove(), 200);
    }, 4000);
}

async function apiFetch(path, opts = {}) {
    try {
        if (!authToken && window.basilisk?._getToken) {
            authToken = await window.basilisk._getToken();
        }
        const headers = { 'Content-Type': 'application/json' };
        if (authToken) headers['X-Basilisk-Token'] = authToken;

        const r = await fetch(`${BRIDGE}${path}`, { headers, ...opts });
        const data = await r.json();
        if (!r.ok || data.error) {
            const err = data.error || `HTTP ${r.status}`;
            toast('error', err);
            return data;
        }
        return data;
    } catch (e) {
        if (backendReady) {
            log('err', `API: ${e.message}`);
            toast('error', `Connection failed: ${e.message}`);
        }
        return { error: e.message };
    }
}

// ── Backend Connection ──
const connDot = document.getElementById('conn-dot');
const connLabel = document.getElementById('conn-label');
let backendReady = false;

async function checkBackend(silent = false) {
    try {
        const r = await fetch(`${BRIDGE}/health`);
        if (r.ok) {
            connDot.classList.add('on');
            connDot.classList.remove('err');
            connLabel.innerText = 'Connected';
            if (!backendReady) {
                log('ok', 'Backend connected.');
                toast('ok', 'Basilisk engine connected.');
                backendReady = true;
            }
            return true;
        }
    } catch {
        if (!silent) {
            connDot.classList.remove('on');
            connDot.classList.add('err');
            connLabel.innerText = 'Offline';
        }
    }
    return false;
}

let poll = setInterval(async () => {
    if (!authToken && window.basilisk?._getToken) {
        authToken = await window.basilisk._getToken();
    }
    if (await checkBackend()) {
        clearInterval(poll);
        loadNative();
        loadModules();
        connectWebSocket();
    }
}, 500);
checkBackend(true);

// ── WebSocket for real-time scan events ──
let ws = null;
let wsRetries = 0;

function connectWebSocket() {
    if (wsRetries >= 5) return;
    try {
        const url = `ws://127.0.0.1:8741/ws${authToken ? `?token=${authToken}` : ''}`;
        ws = new WebSocket(url);
        ws.onopen = () => { wsRetries = 0; log('ok', 'WebSocket connected.'); };
        ws.onmessage = (evt) => {
            try {
                const msg = JSON.parse(evt.data);
                if (msg.event === 'auth_error') {
                    log('err', 'WebSocket Authentication failed.');
                    return;
                }
                handleWSEvent(msg.event, msg.data);
            } catch { }
        };
        ws.onclose = () => {
            wsRetries++;
            if (wsRetries === 1) log('dim', 'WebSocket disconnected — using HTTP polling.');
            if (wsRetries < 5) setTimeout(connectWebSocket, 5000);
        };
        ws.onerror = () => { };
    } catch { }
}

// ── Keyboard Shortcuts ──
document.addEventListener('keydown', e => {
    if (e.ctrlKey || e.metaKey) {
        const map = { '1': 'dashboard', '2': 'scan', '3': 'sessions', '4': 'modules', '5': 'evolution', '6': 'findings', '7': 'diff', '8': 'posture' };
        if (map[e.key]) { document.querySelector(`[data-v="${map[e.key]}"]`)?.click(); e.preventDefault(); }
    }
});

// ── Backend log forwarding ──
if (window.basilisk?.onBackendLog) {
    window.basilisk.onBackendLog(msg => log('dim', msg.trim()));
}
if (window.basilisk?.onBackendError) {
    window.basilisk.onBackendError(msg => log('err', `Backend: ${msg}`));
}

// ── Clear Log ──
document.getElementById('btn-clear-log')?.addEventListener('click', () => {
    const l = document.getElementById('full-log');
    if (l) l.innerHTML = '<div class="ll dim">[system] Log cleared</div>';
});
