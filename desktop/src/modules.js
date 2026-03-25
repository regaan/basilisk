/**
 * Basilisk Desktop — Modules & Evolution Module.
 */

import { esc, setHidden } from './shared.js';
import { apiFetch } from './core.js';

function loadingMessage(text, extraClass = '') {
    return `<div class="grid-status ${extraClass}">${esc(text)}</div>`;
}

export async function loadModules() {
    const grid = document.getElementById('mod-grid');
    if (!grid) return;
    grid.innerHTML = loadingMessage('Loading modules...');

    let moduleList = [];
    try {
        const data = await apiFetch('/api/modules');
        if (data && data.modules) {
            moduleList = data.modules.map((module) => ({
                name: module.name,
                cat: module.category,
                owasp: module.owasp_id || '',
                desc: module.description,
                tier: module.trust_tier || 'beta',
                criteria: module.success_criteria || [],
                requirements: module.evidence_requirements || [],
                defaultEnabled: module.default_enabled !== false,
            }));
        }
    } catch (e) {
        console.error('Failed to load modules:', e);
        grid.innerHTML = loadingMessage('Failed to load modules.', 'grid-status-error');
    }

    if (moduleList.length) {
        grid.innerHTML = '';
        moduleList.forEach((module) => {
            const el = document.createElement('div');
            el.className = 'mod-card';
            const tierClass = module.tier === 'production' ? 'accent-text' : 'text-muted';
            const defaultMarkup = module.defaultEnabled ? '' : ' · <span class="amber-text">default-off</span>';
            el.innerHTML = `<div class="mod-top"><span class="mod-name">${esc(module.name)}</span><span class="badge-owasp">${esc(module.owasp)}</span></div><div class="mod-cat">${esc(module.cat)} · <span class="${tierClass}">${esc(module.tier)}</span>${defaultMarkup}</div><div class="mod-desc">${esc(module.desc)}</div>`;
            el.addEventListener('click', () => {
                const existing = el.querySelector('.mod-detail');
                if (existing) {
                    existing.remove();
                    return;
                }
                const detail = document.createElement('div');
                detail.className = 'mod-detail';
                detail.innerHTML = `<div class="mod-detail-heading">Category: ${esc(module.cat)}</div><div>OWASP ID: <span class="badge-owasp">${esc(module.owasp)}</span></div><div>Tier: <span class="${tierClass}">${esc(module.tier)}</span></div><div class="mod-detail-copy">${esc(module.desc)}</div><div class="mod-detail-heading mod-detail-heading-gap">Success Criteria</div><div class="criteria-list">${module.criteria.map((criterion) => `<div class="criteria-item">${esc(criterion)}</div>`).join('')}</div><div class="mod-detail-heading mod-detail-heading-gap">Required Proof</div><div class="criteria-list">${module.requirements.map((requirement) => `<div class="criteria-item"><code>${esc(requirement)}</code></div>`).join('') || '<div class="criteria-item text-muted">module-specific proof</div>'}</div>`;
                el.appendChild(detail);
            });
            grid.appendChild(el);
        });
        document.getElementById('k-modules').innerText = moduleList.length;
        const countLabel = document.getElementById('mod-count-label');
        if (countLabel) countLabel.innerText = moduleList.length;
    }

    const mutationGrid = document.getElementById('mut-grid');
    if (mutationGrid) {
        mutationGrid.innerHTML = loadingMessage('Loading mutations...');
        try {
            const data = await apiFetch('/api/mutations');
            if (data && data.mutations) {
                mutationGrid.innerHTML = '';
                data.mutations.forEach((mutation) => {
                    const el = document.createElement('div');
                    el.className = 'mod-card';
                    el.innerHTML = `<div class="mod-top"><span class="mod-name">${esc(mutation.name)}</span><span class="badge-sev LOW">${esc(mutation.lang || 'Go')}</span></div><div class="mod-desc">${esc(mutation.description)}</div>`;
                    mutationGrid.appendChild(el);
                });
            }
        } catch (e) {
            console.error('Failed to load mutations:', e);
            mutationGrid.innerHTML = loadingMessage('Failed to load mutations.', 'grid-status-error');
        }
    }

    loadMultiturnModules();
}

let multiturnLoaded = false;
export async function loadMultiturnModules() {
    if (multiturnLoaded) return;
    try {
        const data = await apiFetch('/api/modules/multiturn');
        if (data.error) return;
        multiturnLoaded = true;

        const safe = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.innerText = value;
        };
        if (data.cultivation) safe('mt-cultivation-count', data.cultivation.total_scenarios || 0);
        if (data.authority_escalation) safe('mt-authority-count', data.authority_escalation.total_sequences || 0);
        if (data.sycophancy) safe('mt-sycophancy-count', data.sycophancy.total_sequences || 0);

        const scenarioList = document.getElementById('mt-scenario-list');
        if (scenarioList) {
            scenarioList.innerHTML = '';
            const sections = [
                { label: 'Cultivation', items: data.cultivation?.scenarios || [], className: 'section-header-accent' },
                { label: 'Authority Escalation', items: data.authority_escalation?.sequences || [], className: 'section-header-danger' },
                { label: 'Sycophancy', items: data.sycophancy?.sequences || [], className: 'section-header-amber' },
            ];
            sections.forEach((section) => {
                const header = document.createElement('div');
                header.className = `section-header ${section.className}`;
                header.innerText = `${section.label} (${section.items.length})`;
                scenarioList.appendChild(header);
                section.items.forEach((name) => {
                    const row = document.createElement('div');
                    row.className = 'section-row';
                    row.innerText = name;
                    scenarioList.appendChild(row);
                });
            });
        }

        const featureList = document.getElementById('mt-feature-list');
        if (featureList) {
            featureList.innerHTML = '';
            const allFeatures = {};
            ['cultivation', 'authority_escalation', 'sycophancy'].forEach((module) => {
                if (data[module]?.features) {
                    data[module].features.forEach((feature) => {
                        if (!allFeatures[feature]) allFeatures[feature] = [];
                        allFeatures[feature].push(module);
                    });
                }
            });
            const tbl = document.createElement('table');
            tbl.className = 'tbl';
            tbl.innerHTML = `<thead><tr><th>Feature</th><th>Cult</th><th>Auth</th><th>Syco</th></tr></thead><tbody>${Object.entries(allFeatures).map(([feature, modules]) => `<tr><td class="table-text-primary table-font-small">${esc(feature.replace(/_/g, ' '))}</td><td>${modules.includes('cultivation') ? '<span class="safe-text">✓</span>' : '<span class="text-muted">—</span>'}</td><td>${modules.includes('authority_escalation') ? '<span class="safe-text">✓</span>' : '<span class="text-muted">—</span>'}</td><td>${modules.includes('sycophancy') ? '<span class="safe-text">✓</span>' : '<span class="text-muted">—</span>'}</td></tr>`).join('')}</tbody>`;
            featureList.appendChild(tbl);
        }
    } catch (e) {
        console.error('Failed to load multiturn data:', e);
    }
}

let evolutionLoaded = false;
export async function loadEvolutionOperators() {
    if (evolutionLoaded) return;
    try {
        const data = await apiFetch('/api/evolution/operators');
        if (data.error) return;
        evolutionLoaded = true;
        const safe = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.innerText = value;
        };
        safe('evo-vocab', data.metaphor_vocabulary_size);
        safe('evo-openers', data.opener_variants);
        safe('evo-closers', data.closer_variants);

        const features = document.getElementById('evo-features');
        if (features && data.features) {
            features.innerHTML = '';
            data.features.forEach((feature) => {
                const tag = document.createElement('span');
                tag.className = 'badge-sev LOW feature-tag';
                tag.innerText = feature.replace(/_/g, ' ');
                features.appendChild(tag);
            });
        }
    } catch (e) {
        console.error('Failed to load evolution operators:', e);
    }
}

export function initModules() {
    document.getElementById('mod-search')?.addEventListener('input', (event) => {
        const query = event.target.value.toLowerCase();
        document.querySelectorAll('#mod-grid .mod-card').forEach((card) => {
            setHidden(card, !card.innerText.toLowerCase().includes(query));
        });
    });
}
