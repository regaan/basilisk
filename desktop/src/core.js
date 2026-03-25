/**
 * Basilisk Desktop — Core Module
 * Shared API helpers, notifications, navigation, and backend connection.
 */

import { appState, esc, ts } from './shared.js';

const connDot = document.getElementById('conn-dot');
const connLabel = document.getElementById('conn-label');

export async function apiFetch(path, opts = {}) {
    try {
        let body = opts.body ?? null;
        if (typeof body === 'string') {
            try { body = JSON.parse(body); } catch { /* keep raw */ }
        }
        const data = await window.basilisk.request(path, {
            method: opts.method || 'GET',
            body,
        });
        if (data?.error && !opts.quiet) {
            const err = data.error || 'Request failed';
            if (appState.backendReady || path === '/health') {
                toast('error', err);
            }
            return data;
        }
        return data || {};
    } catch (e) {
        if (!opts.quiet && appState.backendReady) {
            log('err', `API: ${e.message}`);
            toast('error', `Connection failed: ${e.message}`);
        }
        return { error: e.message };
    }
}

export function log(type, msg) {
    [document.getElementById('sys-log'), document.getElementById('full-log')].forEach((el) => {
        if (!el) return;
        const line = document.createElement('div');
        line.className = `ll ${type}`;
        line.innerText = `[${ts()}] ${msg}`;
        el.appendChild(line);
        el.scrollTop = el.scrollHeight;
    });
    if (type === 'err') toast('error', msg);
}

export function toast(type, msg) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const note = document.createElement('div');
    note.className = `toast ${type}`;
    const iconMap = { error: '✕', ok: '✓', inf: 'ℹ' };
    note.innerHTML = `
        <div class="toast-icon">${iconMap[type] || '•'}</div>
        <div class="toast-msg">${esc(msg)}</div>
    `;
    container.appendChild(note);
    setTimeout(() => {
        note.classList.add('removing');
        setTimeout(() => note.remove(), 200);
    }, 4000);
}

function setConnectionState(online) {
    if (!connDot || !connLabel) return;
    connDot.classList.toggle('on', online);
    connDot.classList.toggle('err', !online);
    connLabel.innerText = online ? 'Connected' : 'Offline';
}

export async function checkBackend(silent = false) {
    const health = await apiFetch('/health', { quiet: true });
    if (health && !health.error && health.status === 'online') {
        setConnectionState(true);
        if (!appState.backendReady) {
            log('ok', 'Backend connected.');
            toast('ok', 'Basilisk engine connected.');
            appState.backendReady = true;
        }
        return true;
    }
    if (!silent) {
        setConnectionState(false);
    }
    return false;
}

/**
 * @param {{
 *   onTabChange?: (view: string) => void,
 *   onBackendReady?: () => void,
 *   onBackendEvent?: (event: string, data: any) => void,
 * }} deps
 */
export function initCore(deps = {}) {
    document.getElementById('btn-min')?.addEventListener('click', () => window.basilisk?.send?.('window:minimize'));
    document.getElementById('btn-max')?.addEventListener('click', () => window.basilisk?.send?.('window:maximize'));
    document.getElementById('btn-close')?.addEventListener('click', () => window.basilisk?.send?.('window:close'));

    const tabs = document.querySelectorAll('.tab');
    const views = document.querySelectorAll('.view');
    tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            tabs.forEach((node) => node.classList.remove('active'));
            views.forEach((node) => node.classList.remove('active'));
            tab.classList.add('active');
            const view = document.getElementById(`v-${tab.dataset.v}`);
            if (view) view.classList.add('active');
            deps.onTabChange?.(tab.dataset.v);
        });
    });

    document.addEventListener('keydown', (event) => {
        if (event.ctrlKey || event.metaKey) {
            const shortcuts = {
                1: 'dashboard',
                2: 'scan',
                3: 'sessions',
                4: 'modules',
                5: 'evolution',
                6: 'findings',
                7: 'diff',
                8: 'posture',
            };
            if (shortcuts[event.key]) {
                document.querySelector(`[data-v="${shortcuts[event.key]}"]`)?.click();
                event.preventDefault();
            }
        }
    });

    window.basilisk?.onBackendLog?.((msg) => log('dim', msg.trim()));
    window.basilisk?.onBackendError?.((msg) => log('err', `Backend: ${msg}`));
    window.basilisk?.onBackendEvent?.((msg) => {
        if (msg?.event) {
            deps.onBackendEvent?.(msg.event, msg.data);
        }
    });

    document.getElementById('btn-clear-log')?.addEventListener('click', () => {
        const logView = document.getElementById('full-log');
        if (logView) {
            logView.innerHTML = '<div class="ll dim">[system] Log cleared</div>';
        }
    });

    document.getElementById('btn-open-homepage')?.addEventListener('click', async () => {
        const result = await window.basilisk?.openExternal?.('https://regaan.rothackers.com');
        if (result && !result.success) {
            toast('error', result.error || 'Failed to open homepage');
        }
    });

    const backendPoll = setInterval(async () => {
        if (await checkBackend()) {
            clearInterval(backendPoll);
            deps.onBackendReady?.();
        }
    }, 500);
    checkBackend(true);
}
