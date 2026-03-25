/**
 * Basilisk Desktop — Probes & Eval Module.
 */

import { esc } from './shared.js';
import { apiFetch } from './core.js';

let probesLoaded = false;

export async function loadProbes() {
    const list = document.getElementById('probe-list');
    const statsPanel = document.getElementById('probe-stats');
    if (!list) return;

    const category = document.getElementById('probe-cat')?.value || '';
    const severity = document.getElementById('probe-sev')?.value || '';
    const query = document.getElementById('probe-search')?.value || '';

    list.innerHTML = '<div class="grid-status">Loading probes...</div>';

    try {
        const params = new URLSearchParams();
        if (category) params.set('category', category);
        if (severity) params.set('severity', severity);
        if (query) params.set('query', query);
        params.set('limit', '200');

        const data = await apiFetch(`/api/probes?${params.toString()}`);
        if (!data || !data.probes) {
            list.innerHTML = '<div class="empty-msg">No probes returned.</div>';
            return;
        }

        probesLoaded = true;
        list.innerHTML = '';

        data.probes.forEach((probe) => {
            const el = document.createElement('div');
            const sevClass = probe.severity === 'critical' ? 'danger-text'
                : probe.severity === 'high' ? 'danger-text'
                    : probe.severity === 'medium' ? 'amber-text'
                        : 'text-muted';
            el.className = 'probe-row';
            el.innerHTML = `
                <div class="probe-row-head">
                    <div class="probe-row-title">
                        <span class="probe-id">${esc(probe.id)}</span>
                        <span class="probe-name">${esc(probe.name)}</span>
                    </div>
                    <div class="probe-badges">
                        <span class="badge-owasp probe-owasp">${esc(probe.owasp_id || '')}</span>
                        <span class="probe-pill ${sevClass}">${esc(probe.severity)}</span>
                        <span class="probe-pill accent-pill">${esc(probe.category)}</span>
                    </div>
                </div>`;

            el.addEventListener('click', () => {
                const existing = el.querySelector('.probe-detail');
                if (existing) {
                    existing.remove();
                    return;
                }
                const detail = document.createElement('div');
                detail.className = 'probe-detail';
                detail.textContent = probe.payload;
                if (probe.tags && probe.tags.length) {
                    const tagsEl = document.createElement('div');
                    tagsEl.className = 'probe-tags';
                    probe.tags.forEach((tagName) => {
                        const tag = document.createElement('span');
                        tag.className = 'probe-tag';
                        tag.textContent = tagName;
                        tagsEl.appendChild(tag);
                    });
                    detail.appendChild(tagsEl);
                }
                el.appendChild(detail);
            });

            list.appendChild(el);
        });

        const counter = document.getElementById('k-probes');
        if (counter) counter.innerText = data.total;

        if (statsPanel) {
            const stats = await apiFetch('/api/probes/stats');
            if (stats) renderProbeStats(statsPanel, stats);
        }
    } catch (e) {
        console.error('Failed to load probes:', e);
        list.innerHTML = `<div class="empty-msg danger-text">Failed to load probes: ${esc(e.message)}</div>`;
    }
}

function renderProbeStats(container, stats) {
    container.innerHTML = '';

    const totalEl = document.createElement('div');
    totalEl.className = 'stats-block';
    totalEl.innerHTML = `<div class="stats-title">TOTAL PROBES</div><div class="stats-total-value">${stats.total}</div>`;
    container.appendChild(totalEl);

    if (stats.by_category) {
        const catEl = document.createElement('div');
        catEl.className = 'stats-block';
        catEl.innerHTML = '<div class="stats-title">BY CATEGORY</div>';
        Object.entries(stats.by_category).forEach(([cat, count]) => {
            const pct = Math.round((count / stats.total) * 100);
            const row = document.createElement('div');
            row.className = 'stats-bar-row';
            row.innerHTML = `<div class="stats-bar-label"><span class="table-text-primary">${esc(cat)}</span><span class="text-muted">${count}</span></div><progress class="stats-progress" max="100" value="${pct}"></progress>`;
            catEl.appendChild(row);
        });
        container.appendChild(catEl);
    }

    if (stats.by_severity) {
        const sevEl = document.createElement('div');
        sevEl.className = 'stats-block';
        sevEl.innerHTML = '<div class="stats-title">BY SEVERITY</div>';
        const sevClasses = { critical: 'danger-text', high: 'danger-text', medium: 'amber-text', low: 'text-muted' };
        Object.entries(stats.by_severity).forEach(([sev, count]) => {
            const line = document.createElement('div');
            line.className = 'stats-line';
            line.innerHTML = `<span class="${sevClasses[sev] || 'text-muted'}">${esc(sev)}</span><span class="text-muted">${count}</span>`;
            sevEl.appendChild(line);
        });
        container.appendChild(sevEl);
    }

    if (stats.top_tags && stats.top_tags.length) {
        const tagEl = document.createElement('div');
        tagEl.className = 'stats-block';
        tagEl.innerHTML = '<div class="stats-title">TOP TAGS</div>';
        const wrap = document.createElement('div');
        wrap.className = 'probe-tags';
        stats.top_tags.forEach(([tagName, count]) => {
            const tag = document.createElement('span');
            tag.className = 'probe-tag';
            tag.textContent = `${tagName} (${count})`;
            wrap.appendChild(tag);
        });
        tagEl.appendChild(wrap);
        container.appendChild(tagEl);
    }
}

async function runEval() {
    const yaml = document.getElementById('eval-yaml')?.value;
    const format = document.getElementById('eval-format')?.value || 'json';
    const resultsPanel = document.getElementById('eval-results');
    const summaryLabel = document.getElementById('eval-summary');

    if (!yaml || !yaml.trim()) {
        if (resultsPanel) resultsPanel.innerHTML = '<div class="empty-msg danger-text">Provide a YAML config to run.</div>';
        return;
    }

    if (resultsPanel) resultsPanel.innerHTML = '<div class="grid-status accent-text">Running eval suite...</div>';
    if (summaryLabel) summaryLabel.textContent = 'Running...';

    try {
        const data = await apiFetch('/api/eval/run', {
            method: 'POST',
            body: {
                config_yaml: yaml,
                output_format: format,
            },
        });

        if (!data) {
            if (resultsPanel) resultsPanel.innerHTML = '<div class="empty-msg danger-text">No response from eval runner.</div>';
            return;
        }

        if (summaryLabel && data.summary) {
            const summary = data.summary;
            const passRatePct = (summary.pass_rate ?? 0) * 100;
            const passClass = passRatePct >= 80 ? 'safe-text' : passRatePct >= 50 ? 'amber-text' : 'danger-text';
            summaryLabel.innerHTML = `<span class="${passClass}">${passRatePct.toFixed(1)}%</span> · ${summary.passed ?? 0}/${summary.total ?? 0} passed`;
        }

        if (resultsPanel && data.formatted_output) {
            resultsPanel.innerHTML = '';
            if (data.tests && data.tests.length) {
                data.tests.forEach((test) => {
                    const card = document.createElement('div');
                    card.className = `eval-card ${test.passed ? 'eval-card-pass' : 'eval-card-fail'}`;
                    card.innerHTML = `
                        <div class="eval-card-head">
                            <span class="probe-id">${esc(test.test_id || test.name || 'test')}</span>
                            <span class="${test.passed ? 'safe-text' : 'danger-text'}">${test.passed ? 'PASS' : 'FAIL'}</span>
                        </div>
                        ${(test.assertions || []).map((assertion) => `<div class="eval-assertion">${assertion.passed ? '✓' : '✗'} ${esc(assertion.type)} ${assertion.reason ? `— ${esc(assertion.reason)}` : ''}</div>`).join('')}
                    `;
                    resultsPanel.appendChild(card);
                });
            }

            const raw = document.createElement('details');
            raw.className = 'raw-output';
            raw.innerHTML = `<summary>Raw ${esc(format)} output</summary><pre>${esc(data.formatted_output)}</pre>`;
            resultsPanel.appendChild(raw);
        }
    } catch (e) {
        console.error('Eval run failed:', e);
        if (resultsPanel) resultsPanel.innerHTML = `<div class="empty-msg danger-text">Eval failed: ${esc(e.message)}</div>`;
        if (summaryLabel) summaryLabel.textContent = 'Error';
    }
}

export function initProbesEval() {
    document.getElementById('btn-probe-load')?.addEventListener('click', loadProbes);
    document.getElementById('btn-eval-run')?.addEventListener('click', runEval);
    ['probe-cat', 'probe-sev'].forEach((id) => {
        document.getElementById(id)?.addEventListener('change', () => {
            if (probesLoaded) loadProbes();
        });
    });
    document.getElementById('probe-search')?.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') loadProbes();
    });
}
