import { initCore } from './core.js';
import { handleScanEvent, initScan } from './scan.js';
import { initModules, loadEvolutionOperators, loadModules, loadMultiturnModules } from './modules.js';
import { initSessions, loadNative, loadSecretStoreStatus, loadSessions } from './sessions.js';
import { initAdvanced } from './advanced.js';
import { initProbesEval, loadProbes } from './probes_eval.js';
import { initUpdates } from './updates.js';

function handleTabChange(view) {
    if (view === 'modules') {
        loadModules();
        loadMultiturnModules();
    }
    if (view === 'evolution') loadEvolutionOperators();
    if (view === 'sessions' || view === 'reports') loadSessions();
    if (view === 'settings') {
        loadNative();
        loadSecretStoreStatus();
    }
}

initCore({
    onTabChange: handleTabChange,
    onBackendReady: () => {
        loadNative();
        loadSecretStoreStatus();
        loadModules();
    },
    onBackendEvent: handleScanEvent,
});

initScan();
initModules();
initSessions();
initAdvanced();
initProbesEval();
initUpdates();

loadModules();
loadMultiturnModules();
loadEvolutionOperators();
loadProbes();
