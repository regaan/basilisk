/**
 * Basilisk Desktop — Sessions, Reports, Audit, Settings Module
 */

// ── Sessions ──
async function loadSessions() {
    const data = await apiFetch('/api/sessions');
    const list = document.getElementById('sess-list');
    list.innerHTML = '';
    if (!data.sessions?.length) { list.innerHTML = '<div class="empty-msg">No sessions.</div>'; return; }
    const b = document.getElementById('b-sessions');
    b.innerText = data.sessions.length; b.classList.remove('hidden');
    document.getElementById('k-scans').innerText = data.sessions.length;

    const rptSel = document.getElementById('rpt-sess');
    if (rptSel) {
        rptSel.innerHTML = '<option value="">Select…</option>';
        data.sessions.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.id;
            opt.innerText = `${s.target || s.id.slice(0, 12)} (${s.status})`;
            rptSel.appendChild(opt);
        });
    }

    data.sessions.forEach(s => {
        const el = document.createElement('div');
        el.className = 'sess-item';
        el.innerHTML = `<div class="sess-target">${esc(s.target || s.id?.slice(0, 16))}</div><div class="sess-meta"><span class="badge-sev ${s.status === 'completed' ? 'LOW' : 'MEDIUM'}">${s.status}</span>${s.total_findings ? `<span>${s.total_findings} findings</span>` : ''}</div>`;
        el.addEventListener('click', () => loadSessionDetail(s.id, el));
        list.appendChild(el);
    });
}

async function loadSessionDetail(id, el) {
    const data = await apiFetch(`/api/sessions/${id}`);
    const det = document.getElementById('sess-detail');
    det.innerHTML = '';
    document.querySelectorAll('.sess-item').forEach(i => i.classList.remove('active'));
    el?.classList.add('active');
    if (!data.findings?.length) { det.innerHTML = '<div class="empty-msg">No findings.</div>'; return; }
    const tbl = document.createElement('table');
    tbl.className = 'tbl';
    tbl.innerHTML = `<thead><tr><th>Severity</th><th>Module</th><th>Title</th><th>Conf</th></tr></thead><tbody>${data.findings.map(f => `<tr><td><span class="badge-sev ${f.severity}">${f.severity}</span></td><td style="font-size:10px">${esc(f.attack_module || '—')}</td><td style="color:var(--text-1)">${esc(f.title)}</td><td>${f.confidence ? `${(f.confidence * 100).toFixed(0)}%` : '—'}</td></tr>`).join('')}</tbody>`;
    det.appendChild(tbl);
}

document.getElementById('btn-refresh-sess')?.addEventListener('click', loadSessions);

// ── Native Status ──
async function loadNative() {
    const d = await apiFetch('/api/native/status');
    if (d.error) return;
    const map = { fuzzer_go: 'ns-fuzzer', matcher_go: 'ns-matcher', tokens_c: 'ns-tokens', encoder_c: 'ns-encoder' };
    Object.entries(map).forEach(([k, id]) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (d[k]) { el.innerText = 'LOADED'; el.className = 'native-val ok'; }
        else { el.innerText = 'FALLBACK'; el.className = 'native-val fb'; }
    });
    const loaded = Object.values(d).filter(Boolean).length;
    log(loaded > 0 ? 'ok' : 'dim', `Native: ${loaded}/${Object.keys(d).length} loaded`);
}

// ── API Keys ──
window.saveKey = async function (prov) {
    const inp = document.getElementById(`key-${prov}`);
    if (!inp) return;
    const res = await apiFetch('/api/settings/apikey', { method: 'POST', body: JSON.stringify({ provider: prov, key: inp.value }) });
    if (!res.error) {
        log('ok', `Key saved: ${prov}`);
        toast('ok', `${prov.toUpperCase()} API key saved.`);
    }
};

// ── Reports ──
document.getElementById('btn-gen-report')?.addEventListener('click', async () => {
    const sid = document.getElementById('rpt-sess')?.value;
    const fmt = document.getElementById('rpt-fmt')?.value;
    if (!sid) { log('err', 'Select a session first.'); return; }
    log('inf', `Generating ${fmt} report…`);
    if (window.basilisk?.report) {
        const r = await window.basilisk.report.export(sid, fmt);
        if (r.path) {
            log('ok', `Exported: ${r.path}`);
            toast('ok', `Report exported to ${r.path}`);
        }
    } else {
        const r = await apiFetch(`/api/report/${sid}`, { method: 'POST', body: JSON.stringify({ format: fmt, open_browser: true }) });
        if (r.path) {
            log('ok', `Generated: ${r.path}`);
            toast('ok', `Report generated and opening in browser...`);
        }
    }
});

// ── Audit Log ──
document.getElementById('btn-audit-load')?.addEventListener('click', async () => {
    const sessionId = document.getElementById('audit-session')?.value?.trim();
    if (!sessionId) { log('err', 'Enter a session ID.'); return; }

    try {
        const result = await apiFetch(`/api/audit/${sessionId}`);
        const container = document.getElementById('audit-log');
        const integrity = document.getElementById('audit-integrity');

        if (result.error) {
            container.innerHTML = `<div class="empty-msg" style="color:var(--danger)">${esc(result.error)}</div>`;
            return;
        }

        container.innerHTML = '';
        const entries = result.entries || [];
        const eventColors = {
            session_start: 'dim', scan_config: 'dim', prompt_sent: 'inf',
            response_received: 'dim', finding_discovered: 'ok', evolution_generation: 'inf',
            error: 'err', report_generated: 'ok', session_end: 'dim',
        };

        entries.forEach(entry => {
            const el = document.createElement('div');
            const cls = eventColors[entry.event] || 'dim';
            el.className = `ll ${cls}`;
            const t = entry.timestamp?.slice(11, 19) || '';
            let detail = '';
            if (entry.event === 'finding_discovered') {
                detail = `[${entry.data?.severity}] ${entry.data?.title || ''}`;
            } else if (entry.event === 'prompt_sent') {
                detail = `${entry.data?.module} → ${entry.data?.provider}/${entry.data?.model}`;
            } else if (entry.event === 'error') {
                detail = `${entry.data?.module}: ${entry.data?.error?.slice(0, 80)}`;
            } else if (entry.event === 'evolution_generation') {
                detail = `Gen ${entry.data?.generation} best=${entry.data?.best_fitness} breakthroughs=${entry.data?.breakthroughs}`;
            } else {
                detail = JSON.stringify(entry.data || {}).slice(0, 100);
            }
            el.innerText = `[${t}] ${entry.event}: ${detail}`;
            container.appendChild(el);
        });

        integrity.innerText = `${entries.length} entries | File: ${result.path || '?'} | Chain integrity: SHA-256 checksummed`;
        log('ok', `Loaded ${entries.length} audit entries for session ${sessionId}`);
    } catch (e) {
        log('err', `Audit load failed: ${e.message}`);
    }
});
