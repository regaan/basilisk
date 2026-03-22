/**
 * Basilisk Desktop — Advanced Scans Module
 * Differential scan and Posture assessment.
 */

// ── Differential Scan ──
let diffTargetCount = 2;

document.getElementById('btn-diff-add')?.addEventListener('click', () => {
    const container = document.getElementById('diff-targets');
    const idx = diffTargetCount++;
    const row = document.createElement('div');
    row.className = 'diff-target-row';
    row.dataset.idx = idx;
    row.innerHTML = `
        <select class="sel" id="diff-prov-${idx}" style="width:130px">
            <option value="openai">OpenAI</option><option value="anthropic">Anthropic</option>
            <option value="google" ${idx === 2 ? 'selected' : ''}>Google</option><option value="xai">xAI (Grok)</option><option value="azure">Azure</option><option value="ollama">Ollama</option>
        </select>
        <input class="inp" id="diff-model-${idx}" placeholder="${idx === 2 ? 'gemini/gemini-2.0-flash' : ''}" style="flex:1">
        <button class="btn ghost sm" onclick="this.parentElement.remove()">✗</button>
    `;
    container.appendChild(row);
});

document.getElementById('btn-diff-start')?.addEventListener('click', async () => {
    const rows = document.querySelectorAll('.diff-target-row');
    const targets = [];
    rows.forEach(row => {
        const idx = row.dataset.idx;
        const prov = document.getElementById(`diff-prov-${idx}`)?.value;
        const model = document.getElementById(`diff-model-${idx}`)?.value || '';
        if (prov) targets.push({ provider: prov, model, api_key: '' });
    });

    if (targets.length < 2) {
        log('err', 'Need at least 2 targets for differential scan.');
        return;
    }

    const btn = document.getElementById('btn-diff-start');
    btn.disabled = true;
    btn.innerText = 'Scanning…';
    log('inf', `Starting differential scan across ${targets.length} models…`);

    try {
        const result = await apiFetch('/api/diff', {
            method: 'POST',
            body: JSON.stringify({ targets, categories: [] }),
        });

        const container = document.getElementById('diff-results');
        const summary = document.getElementById('diff-summary');

        if (result.error) {
            container.innerHTML = `<div class="empty-msg" style="color:var(--danger)">${esc(result.error)}</div>`;
            log('err', result.error);
            return;
        }

        summary.innerText = `${result.total_divergences} divergences / ${result.total_probes} probes (${result.divergence_rate})`;

        const tbl = document.createElement('table');
        tbl.className = 'tbl';
        tbl.innerHTML = `<thead><tr><th>Category</th><th>Probe</th><th>Divergence</th><th style="color:var(--danger)">Vulnerable</th><th style="color:var(--safe)">Resistant</th></tr></thead><tbody>
            ${(result.probes || []).map(p => `<tr>
                <td style="font-size:10px">${esc(p.category)}</td>
                <td style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.probe.slice(0, 60))}</td>
                <td><span class="badge-sev ${p.has_divergence ? 'CRITICAL' : 'INFO'}">${p.has_divergence ? 'YES' : 'no'}</span></td>
                <td style="font-size:10px;color:var(--danger)">${p.vulnerable_models?.join(', ') || '—'}</td>
                <td style="font-size:10px;color:var(--safe)">${p.resistant_models?.join(', ') || '—'}</td>
            </tr>`).join('')}</tbody>`;
        container.innerHTML = '';
        container.appendChild(tbl);

        log('ok', `Differential scan complete: ${result.total_divergences} divergences found`);
    } catch (e) {
        log('err', `Diff scan failed: ${e.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3" /></svg>Run Differential';
    }
});

// ── Posture Scan ──
document.getElementById('btn-posture-start')?.addEventListener('click', async () => {
    const provider = document.getElementById('post-provider')?.value || 'openai';
    const model = document.getElementById('post-model')?.value || '';

    const btn = document.getElementById('btn-posture-start');
    btn.disabled = true;
    btn.innerText = 'Scanning…';
    log('inf', `Running posture scan: ${provider}/${model || 'default'}…`);

    try {
        const result = await apiFetch('/api/posture', {
            method: 'POST',
            body: JSON.stringify({ target: '', provider, model, api_key: '' }),
        });

        if (result.error) {
            log('err', result.error);
            return;
        }

        const gradeEl = document.getElementById('posture-grade');
        const scoreEl = document.getElementById('posture-score');
        const kPosture = document.getElementById('k-posture');
        const gradeColors = { 'A+': '#22c55e', 'A': '#22c55e', 'B': '#3b82f6', 'C': '#eab308', 'D': '#ef4444', 'F': '#dc2626' };
        gradeEl.innerText = result.overall_grade || '—';
        gradeEl.style.color = gradeColors[result.overall_grade] || 'var(--text-3)';
        scoreEl.innerText = `${(result.overall_score * 100).toFixed(0)}% coverage`;
        if (kPosture) { kPosture.innerText = result.overall_grade; kPosture.style.color = gradeColors[result.overall_grade]; }

        const container = document.getElementById('posture-results');
        const strengthColors = { none: 'CRITICAL', weak: 'HIGH', moderate: 'MEDIUM', strong: 'LOW', aggressive: 'INFO' };
        const tbl = document.createElement('table');
        tbl.className = 'tbl';
        tbl.innerHTML = `<thead><tr><th>Category</th><th>Strength</th><th>Score</th><th>Benign OK</th><th>Mod Block</th><th>Adv Block</th></tr></thead><tbody>
            ${(result.categories || []).map(c => `<tr>
                <td style="color:var(--text-1)">${esc(c.name)}</td>
                <td><span class="badge-sev ${strengthColors[c.strength] || 'INFO'}">${c.strength.toUpperCase()}</span></td>
                <td>${(c.score * 100).toFixed(0)}%</td>
                <td>${c.benign_allowed ? '✓' : '✗'}</td>
                <td>${c.moderate_blocked ? '✓' : '✗'}</td>
                <td>${c.adversarial_blocked ? '✓' : '✗'}</td>
            </tr>`).join('')}</tbody>`;
        container.innerHTML = '';
        container.appendChild(tbl);

        if (result.recommendations?.length) {
            const recs = document.createElement('div');
            recs.style.cssText = 'padding:12px 16px;font-size:11px;color:var(--text-2);border-top:1px solid var(--border)';
            recs.innerHTML = '<div style="font-weight:600;margin-bottom:6px;color:var(--text-1)">📋 Recommendations</div>' +
                result.recommendations.map(r => `<div style="margin-bottom:4px">• ${esc(r)}</div>`).join('');
            container.appendChild(recs);
        }

        log('ok', `Posture scan complete: Grade ${result.overall_grade} (${(result.overall_score * 100).toFixed(0)}%)`);
    } catch (e) {
        log('err', `Posture scan failed: ${e.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>Run Posture Scan';
    }
});
