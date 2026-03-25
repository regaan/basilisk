/**
 * Shared typed state and renderer utilities.
 *
 * @typedef {{
 *   currentSession: string | null,
 *   allFindings: Array<Record<string, any>>,
 *   scanning: boolean,
 *   timerInterval: ReturnType<typeof setInterval> | null,
 *   timerStart: number | null,
 *   backendReady: boolean,
 *   pendingStop: boolean,
 * }} AppState
 */

/** @type {AppState} */
export const appState = {
    currentSession: null,
    allFindings: [],
    scanning: false,
    timerInterval: null,
    timerStart: null,
    backendReady: false,
    pendingStop: false,
};

export const csvList = (value) => String(value || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

export const esc = (value) => {
    const node = document.createElement('div');
    node.innerText = value || '';
    return node.innerHTML;
};

export const trunc = (value, max = 100) => {
    const text = typeof value === 'string' ? value : JSON.stringify(value || '');
    return text.length > max ? `${text.slice(0, max)}...` : text;
};

export const ts = () => new Date().toLocaleTimeString('en-US', { hour12: false });

export function normalizeSeverity(severity) {
    const normalized = String(severity || 'info').trim().toUpperCase();
    return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(normalized) ? normalized : 'INFO';
}

export function severityClass(severity) {
    return normalizeSeverity(severity);
}

export function statusBadgeClass(status) {
    const normalized = String(status || '').trim().toLowerCase();
    if (normalized === 'completed' || normalized === 'complete') return 'LOW';
    if (normalized === 'running' || normalized === 'resuming') return 'INFO';
    if (normalized === 'failed' || normalized === 'error') return 'HIGH';
    return 'MEDIUM';
}

export function setHidden(element, hidden) {
    if (!element) return;
    element.classList.toggle('is-hidden', hidden);
}

export function showElement(element, displayClass = 'display-flex') {
    if (!element) return;
    element.classList.remove('is-hidden');
    if (displayClass) {
        element.classList.add(displayClass);
    }
}

export function hideElement(element, displayClass = 'display-flex') {
    if (!element) return;
    if (displayClass) {
        element.classList.remove(displayClass);
    }
    element.classList.add('is-hidden');
}

export function toggleVisibility(element, displayClass = 'display-block') {
    if (!element) return;
    const hidden = element.classList.contains('is-hidden');
    if (hidden) {
        showElement(element, displayClass);
    } else {
        hideElement(element, displayClass);
    }
}

export function setProgress(progressEl, percent) {
    if (!progressEl) return;
    const bounded = Math.max(0, Math.min(100, Number.isFinite(percent) ? percent : 0));
    progressEl.value = bounded;
    progressEl.setAttribute('aria-valuenow', String(Math.round(bounded)));
}
