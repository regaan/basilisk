/**
 * Basilisk Desktop — Scan Module
 * WebSocket event handling, scan lifecycle, findings, severity, timer.
 */

// ── WebSocket Event Handler ──
function handleWSEvent(event, data) {
    switch (event) {
        case 'scan:status':
            log('inf', `Scan phase: ${data.phase}`);
            if (data.phase === 'evolving') {
                const phase = document.getElementById('scan-phase');
                if (phase) phase.innerText = 'Smart Prompt Evolution...';
                log('inf', 'Starting AI-powered prompt evolution loop...');
            }
            break;
        case 'scan:progress':
            if (data.progress !== undefined) {
                const bar = document.getElementById('scan-bar');
                if (bar) bar.style.width = `${Math.round(data.progress * 100)}%`;
            }
            if (data.module) {
                const phase = document.getElementById('scan-phase');
                if (phase) phase.innerText = data.module;
            }
            break;
        case 'scan:evolution_stats':
            if (data.stats) {
                const s = data.stats;
                const phase = document.getElementById('scan-phase');
                if (phase) phase.innerText = `Evolution Gen ${s.generation} | Best: ${s.best_fitness?.toFixed(2)} | BT: ${s.breakthroughs}`;

                const bar = document.getElementById('scan-bar');
                if (bar && s.generation && s.total_generations) {
                    bar.style.width = `${Math.round((s.generation / s.total_generations) * 100)}%`;
                }

                const safe = (id, val) => { const el = document.getElementById(id); if (el && val !== undefined) el.innerText = val; };
                safe('evo-gen', s.generation);
                safe('evo-pop', s.population_size || s.pop_size);
                safe('evo-fit', s.best_fitness?.toFixed(3));
                safe('evo-mean', s.mean_fitness?.toFixed(3));
                safe('evo-diversity', s.diversity !== undefined ? `${(s.diversity * 100).toFixed(0)}%` : undefined);
                safe('evo-stagnation', s.stagnation_counter);
                safe('evo-mutrate', s.mutation_rate !== undefined ? `${(s.mutation_rate * 100).toFixed(0)}%` : undefined);
            }
            break;
        case 'scan:finding':
            if (data.finding) {
                if (!allFindings.find(x => x.title === data.finding.title && x.attack_module === data.finding.attack_module)) {
                    allFindings.push(data.finding);
                    addFinding(document.getElementById('live-findings'), data.finding);
                    addFinding(document.getElementById('dash-findings'), data.finding);
                    log('err', `VULN [${data.finding.severity}] ${data.finding.title}`);
                    updateSev();
                    updateTable();
                    const lc = document.getElementById('live-count');
                    if (lc) lc.innerText = `${allFindings.length} detected`;
                    document.getElementById('k-findings').innerText = allFindings.length;
                }
            }
            break;
        case 'scan:profile':
            if (data.profile) updateRecon(data.profile);
            break;
        case 'scan:complete':
            log('ok', `Scan complete. ${data.total_findings} findings.`);
            const barFinal = document.getElementById('scan-bar');
            if (barFinal) barFinal.style.width = '100%';
            resetScan();
            const p = document.getElementById('k-posture');
            if (allFindings.length === 0) { p.innerText = 'SECURE'; p.className = 'kpi-value safe'; }
            else {
                const hasCrit = allFindings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
                p.innerText = hasCrit ? 'COMPROMISED' : 'AT RISK';
                p.className = `kpi-value ${hasCrit ? 'danger' : 'warn'}`;
            }
            break;
        case 'scan:error':
            log('err', `Scan error: ${data.error}`);
            resetScan();
            break;
    }
}

function updateRecon(profile) {
    const safe = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val || '—'; };
    safe('r-model', profile.model_family);
    safe('r-creator', profile.creator);
    safe('r-ctx', profile.context_window ? `${profile.context_window}` : null);
    safe('r-guard', profile.has_guardrails ? 'Yes' : 'No');
    safe('r-tools', profile.has_tools ? 'Yes' : 'No');
    safe('r-rag', profile.has_rag ? 'Yes' : 'No');
}

// ── Timer ──
const timerEl = document.getElementById('scan-timer');
function startTimer() {
    timerStart = Date.now();
    timerEl.classList.add('on');
    timerInterval = setInterval(() => {
        const s = Math.floor((Date.now() - timerStart) / 1000);
        timerEl.innerText = `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
    }, 1000);
}
function stopTimer() { clearInterval(timerInterval); timerEl.classList.remove('on'); }

// ── Scan Controls ──
const btnStart = document.getElementById('btn-scan-start');
const btnStop = document.getElementById('btn-scan-stop');
const progressPane = document.getElementById('scan-progress-pane');
const scanBar = document.getElementById('scan-bar');
const scanPhase = document.getElementById('scan-phase');
const scanPill = document.getElementById('scan-mode-pill');
const liveFindings = document.getElementById('live-findings');
const liveCount = document.getElementById('live-count');
const scanDot = document.getElementById('scan-dot');

btnStart.addEventListener('click', async () => {
    const target = document.getElementById('s-target').value.trim();
    if (!target) { log('err', 'Target URL required.'); return; }

    const cfg = {
        target,
        provider: document.getElementById('s-provider').value,
        model: document.getElementById('s-model').value,
        api_key: document.getElementById('s-apikey').value,
        mode: document.getElementById('s-mode').value,
        evolve: true,
        generations: parseInt(document.getElementById('s-gens').value) || 5,
        output_format: document.getElementById('s-format').value,
        skip_recon: document.getElementById('s-skip-recon').checked,
        recon_modules: Array.from(document.querySelectorAll('.recon-mod:checked')).map(el => el.value),
        modules: [],
        attacker_provider: document.getElementById('s-attacker-provider').value,
        attacker_model: document.getElementById('s-attacker-model').value,
        attacker_api_key: document.getElementById('s-attacker-key').value,
        population_size: parseInt(document.getElementById('s-pop-size').value) || 10,
        fitness_threshold: parseFloat(document.getElementById('s-fitness-threshold').value) || 0.9,
        stagnation_limit: parseInt(document.getElementById('s-stagnation').value) || 3,
    };

    btnStart.style.display = 'none';
    btnStop.style.display = 'flex';
    progressPane.style.display = 'block';
    scanBar.style.width = '0%';
    liveFindings.innerHTML = '';
    allFindings = [];
    scanning = true;
    scanDot.classList.remove('hidden');
    scanPill.className = `mode-pill ${cfg.mode}`;
    scanPill.innerText = cfg.mode.toUpperCase();
    startTimer();
    log('inf', `Starting ${cfg.mode} scan → ${target}`);

    const res = await apiFetch('/api/scan', { method: 'POST', body: JSON.stringify(cfg) });
    if (res.session_id) {
        currentSession = res.session_id;
        log('ok', `Session: ${currentSession}`);
        toast('ok', `Scan started successfully! (Session: ${currentSession.slice(0, 8)})`);
        pollScan();
    } else {
        log('err', `Scan failed: ${res.error || 'Unknown'}`);
        resetScan();
    }
});

btnStop.addEventListener('click', async () => {
    if (currentSession) {
        await apiFetch(`/api/scan/${currentSession}/stop`, { method: 'POST' });
        log('inf', 'Scan stopped.');
        toast('inf', 'Scan stopped by user.');
        resetScan();
    }
});

window.toggleReconDetails = () => {
    const el = document.getElementById('recon-details');
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
};

window.toggleAttackerDetails = () => {
    const el = document.getElementById('attacker-details');
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
};

function resetScan() {
    btnStart.style.display = 'flex';
    btnStop.style.display = 'none';
    scanning = false;
    stopTimer();
    scanDot.classList.add('hidden');
}

async function pollScan() {
    if (!scanning || !currentSession) return;
    const st = await apiFetch(`/api/scan/${currentSession}`);
    if (st.error) { setTimeout(pollScan, 3000); return; }

    if (st.findings_count !== undefined) {
        liveCount.innerText = `${st.findings_count} detected`;
        document.getElementById('k-findings').innerText = st.findings_count;
    }

    if (st.findings) {
        st.findings.forEach(f => {
            if (!allFindings.find(x => x.title === f.title && x.attack_module === f.attack_module)) {
                allFindings.push(f);
                addFinding(liveFindings, f);
                addFinding(document.getElementById('dash-findings'), f);
                log('err', `VULN [${f.severity}] ${f.title}`);
            }
        });
        updateSev();
        updateTable();
    }

    if (st.status === 'complete' || st.status === 'completed') {
        scanBar.style.width = '100%';
        log('ok', `Done. ${allFindings.length} findings.`);
        resetScan();
        const p = document.getElementById('k-posture');
        if (allFindings.length === 0) { p.innerText = 'SECURE'; p.className = 'kpi-value safe'; }
        else {
            const crit = allFindings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
            p.innerText = crit ? 'COMPROMISED' : 'AT RISK';
            p.className = `kpi-value ${crit ? 'danger' : 'warn'}`;
        }
        return;
    }

    if (st.status?.startsWith('attacking:')) scanPhase.innerText = st.status.split(':')[1];
    setTimeout(pollScan, 2000);
}

// ── Finding Card ──
function addFinding(container, f) {
    if (container.querySelector('.empty-msg')) container.innerHTML = '';
    const sev = f.severity || 'MEDIUM';
    const el = document.createElement('div');
    el.className = `fc ${sev}`;
    el.dataset.severity = sev;
    el.innerHTML = `
        <div class="fc-top"><span class="fc-name">${esc(f.title || f.type || 'Finding')}</span><div class="fc-tags"><span class="badge-owasp">${esc(f.owasp_id || f.category || '')}</span><span class="badge-sev ${sev}">${sev}</span></div></div>
        <div class="fc-desc">${esc(f.description || '')}</div>
        ${f.payload ? `<div class="fc-payload">${esc(trunc(f.payload, 200))}</div>` : ''}
        ${f.confidence !== undefined ? `<div class="fc-conf">Confidence: ${(f.confidence * 100).toFixed(0)}%</div>` : ''}
    `;
    container.insertBefore(el, container.firstChild);
}

// ── Severity Counts ──
function updateSev() {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    allFindings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
    document.getElementById('sc-crit').innerText = c.CRITICAL;
    document.getElementById('sc-high').innerText = c.HIGH;
    document.getElementById('sc-med').innerText = c.MEDIUM;
    document.getElementById('sc-low').innerText = c.LOW;
    const b = document.getElementById('b-findings');
    if (allFindings.length > 0) { b.innerText = allFindings.length; b.classList.remove('hidden'); }
}

// ── Findings Table ──
function updateTable() {
    const tb = document.getElementById('find-tbody');
    tb.innerHTML = '';
    if (!allFindings.length) { tb.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-3);padding:24px">No findings.</td></tr>'; return; }
    allFindings.forEach(f => {
        const tr = document.createElement('tr');
        tr.dataset.severity = f.severity;
        tr.innerHTML = `<td><span class="badge-sev ${f.severity}">${f.severity}</span></td><td><span class="badge-owasp">${esc(f.owasp_id || f.category || '—')}</span></td><td>${esc(f.attack_module || '—')}</td><td style="color:var(--text-1)">${esc(f.title || '—')}</td><td>${f.confidence ? `${(f.confidence * 100).toFixed(0)}%` : '—'}</td>`;
        tb.appendChild(tr);
    });
}

// ── Filters ──
document.querySelectorAll('.filters').forEach(bar => {
    bar.querySelectorAll('.fbtn').forEach(btn => {
        btn.addEventListener('click', () => {
            bar.querySelectorAll('.fbtn').forEach(b => b.classList.remove('on'));
            btn.classList.add('on');
            const sev = btn.dataset.sev;
            const container = bar.closest('.pane')?.querySelector('.pane-body, tbody');
            if (!container) return;
            container.querySelectorAll('.fc, tr[data-severity]').forEach(el => {
                el.style.display = sev === 'all' ? '' : (el.dataset.severity === sev ? '' : 'none');
            });
        });
    });
});
