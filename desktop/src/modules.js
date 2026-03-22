/**
 * Basilisk Desktop — Modules & Evolution Module
 * Attack module registry, multi-turn breakdown, evolution operators.
 */

// ── Attack Modules ──
async function loadModules() {
    const grid = document.getElementById('mod-grid');
    if (!grid) return;
    grid.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding: 20px;">Loading modules...</div>';

    let moduleList = [];
    try {
        const data = await apiFetch('/api/modules');
        if (data && data.modules) {
            moduleList = data.modules.map(m => ({
                name: m.name, cat: m.category, owasp: m.owasp_id || '', desc: m.description
            }));
        }
    } catch (e) {
        console.error('Failed to load modules:', e);
        grid.innerHTML = '<div style="grid-column: 1/-1; text-align:center; color: var(--danger);">Failed to load modules.</div>';
    }

    if (moduleList.length) {
        grid.innerHTML = '';
        moduleList.forEach(m => {
            const el = document.createElement('div');
            el.className = 'mod-card';
            el.innerHTML = `<div class="mod-top"><span class="mod-name">${esc(m.name)}</span><span class="badge-owasp">${esc(m.owasp)}</span></div><div class="mod-cat">${esc(m.cat)}</div><div class="mod-desc">${esc(m.desc)}</div>`;
            el.addEventListener('click', () => {
                const existing = el.querySelector('.mod-detail');
                if (existing) { existing.remove(); return; }
                const detail = document.createElement('div');
                detail.className = 'mod-detail';
                detail.style.cssText = 'margin-top:8px;padding:8px 10px;background:var(--bg-surface);border-radius:4px;font-size:11px;color:var(--text-2);border:1px solid var(--border)';
                detail.innerHTML = `<div style="margin-bottom:4px;color:var(--text-1);font-weight:600">Category: ${esc(m.cat)}</div><div>OWASP ID: <span class="badge-owasp">${esc(m.owasp)}</span></div><div style="margin-top:4px">${esc(m.desc)}</div>`;
                el.appendChild(detail);
            });
            grid.appendChild(el);
        });
        document.getElementById('k-modules').innerText = moduleList.length;
        const countLabel = document.getElementById('mod-count-label');
        if (countLabel) countLabel.innerText = moduleList.length;
    }

    // Mutation Operators
    const mg = document.getElementById('mut-grid');
    if (mg) {
        mg.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding: 20px;">Loading mutations...</div>';
        try {
            const data = await apiFetch('/api/mutations');
            if (data && data.mutations) {
                mg.innerHTML = '';
                data.mutations.forEach(m => {
                    const el = document.createElement('div');
                    el.className = 'mod-card';
                    el.innerHTML = `<div class="mod-top"><span class="mod-name">${esc(m.name)}</span><span class="badge-sev LOW">${esc(m.lang || 'Go')}</span></div><div class="mod-desc">${esc(m.description)}</div>`;
                    mg.appendChild(el);
                });
            }
        } catch (e) {
            console.error('Failed to load mutations:', e);
            mg.innerHTML = '<div style="grid-column: 1/-1; text-align:center; color: var(--danger);">Failed to load mutations.</div>';
        }
    }

    loadMultiturnModules();
}

// ── Multi-turn Module Breakdown ──
let mtLoaded = false;
async function loadMultiturnModules() {
    if (mtLoaded) return;
    try {
        const data = await apiFetch('/api/modules/multiturn');
        if (data.error) return;
        mtLoaded = true;

        const safe = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
        if (data.cultivation) safe('mt-cultivation-count', data.cultivation.total_scenarios || 0);
        if (data.authority_escalation) safe('mt-authority-count', data.authority_escalation.total_sequences || 0);
        if (data.sycophancy) safe('mt-sycophancy-count', data.sycophancy.total_sequences || 0);

        const sl = document.getElementById('mt-scenario-list');
        if (sl) {
            sl.innerHTML = '';
            const sections = [
                { label: 'Cultivation', items: data.cultivation?.scenarios || [], color: 'var(--accent)' },
                { label: 'Authority Escalation', items: data.authority_escalation?.sequences || [], color: '#ef4444' },
                { label: 'Sycophancy', items: data.sycophancy?.sequences || [], color: '#eab308' },
            ];
            sections.forEach(sec => {
                const h = document.createElement('div');
                h.style.cssText = `padding:8px 12px;font-size:11px;font-weight:600;color:${sec.color};border-bottom:1px solid var(--border);background:rgba(0,0,0,0.1)`;
                h.innerText = `${sec.label} (${sec.items.length})`;
                sl.appendChild(h);
                sec.items.forEach(name => {
                    const r = document.createElement('div');
                    r.style.cssText = 'padding:4px 12px 4px 20px;font-size:10px;color:var(--text-2);border-bottom:1px solid var(--border)';
                    r.innerText = name;
                    sl.appendChild(r);
                });
            });
        }

        const fl = document.getElementById('mt-feature-list');
        if (fl) {
            fl.innerHTML = '';
            const allFeatures = {};
            ['cultivation', 'authority_escalation', 'sycophancy'].forEach(mod => {
                if (data[mod]?.features) {
                    data[mod].features.forEach(f => {
                        if (!allFeatures[f]) allFeatures[f] = [];
                        allFeatures[f].push(mod);
                    });
                }
            });
            const tbl = document.createElement('table');
            tbl.className = 'tbl';
            tbl.innerHTML = `<thead><tr><th>Feature</th><th>Cult</th><th>Auth</th><th>Syco</th></tr></thead>
                <tbody>${Object.entries(allFeatures).map(([feat, mods]) => `<tr>
                    <td style="font-size:10px;color:var(--text-1)">${esc(feat.replace(/_/g, ' '))}</td>
                    <td>${mods.includes('cultivation') ? '<span style="color:var(--safe)">\u2713</span>' : '<span style="color:var(--text-3)">\u2014</span>'}</td>
                    <td>${mods.includes('authority_escalation') ? '<span style="color:var(--safe)">\u2713</span>' : '<span style="color:var(--text-3)">\u2014</span>'}</td>
                    <td>${mods.includes('sycophancy') ? '<span style="color:var(--safe)">\u2713</span>' : '<span style="color:var(--text-3)">\u2014</span>'}</td>
                </tr>`).join('')}</tbody>`;
            fl.appendChild(tbl);
        }
    } catch (e) {
        console.error('Failed to load multiturn data:', e);
    }
}

// ── Evolution Engine Operators ──
let evoLoaded = false;
async function loadEvolutionOperators() {
    if (evoLoaded) return;
    try {
        const data = await apiFetch('/api/evolution/operators');
        if (data.error) return;
        evoLoaded = true;

        const safe = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
        safe('evo-vocab', data.metaphor_vocabulary_size);
        safe('evo-openers', data.opener_variants);
        safe('evo-closers', data.closer_variants);

        const fc = document.getElementById('evo-features');
        if (fc && data.features) {
            fc.innerHTML = '';
            data.features.forEach(f => {
                const tag = document.createElement('span');
                tag.className = 'badge-sev LOW';
                tag.style.cssText = 'margin:2px 4px;display:inline-block;font-size:10px';
                tag.innerText = f.replace(/_/g, ' ');
                fc.appendChild(tag);
            });
        }
    } catch (e) {
        console.error('Failed to load evolution operators:', e);
    }
}

// Module search
document.getElementById('mod-search')?.addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('#mod-grid .mod-card').forEach(c => {
        c.style.display = c.innerText.toLowerCase().includes(q) ? '' : 'none';
    });
});
