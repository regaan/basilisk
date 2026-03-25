/**
 * Basilisk Desktop — Auto-update module.
 */

import { log, toast } from './core.js';

const RELEASES_URL = 'https://github.com/regaan/basilisk/releases';

const updateBanner = document.getElementById('update-banner');
const updateText = document.getElementById('update-banner-text');
const updateDownloadBtn = document.getElementById('btn-update-download');
const updateInstallBtn = document.getElementById('btn-update-install');
const updateDismissBtn = document.getElementById('btn-update-dismiss');
const updateProgressBar = document.getElementById('update-progress-bar');
const updateProgressFill = document.getElementById('update-progress-fill');
const updateStatus = document.getElementById('update-status');
const updateTrust = document.getElementById('update-build-trust');
const updateCheckBtn = document.getElementById('btn-check-update');

let updateMode = {
    manualOnly: true,
    displayLabel: 'Community Build',
};

function showBanner(text) {
    if (updateBanner) {
        updateBanner.classList.remove('hidden');
        updateText.innerText = text;
    }
}

function setProgressDisplay(percent) {
    updateProgressBar?.classList.remove('hidden');
    updateProgressFill.value = percent;
}

async function loadUpdateStatus() {
    if (!window.basilisk?.update?.getStatus) return;
    const status = await window.basilisk.update.getStatus();
    updateMode = {
        manualOnly: !status.enabled,
        displayLabel: status.display_label || 'Community Build',
    };
    if (updateStatus) {
        updateStatus.innerText = status.enabled ? 'Vendor-signed auto-update enabled' : `${updateMode.displayLabel} · manual updates only`;
    }
    if (updateTrust) {
        const suffix = status.warning ? ` — ${status.warning}` : '';
        updateTrust.innerText = `${updateMode.displayLabel}${suffix}`;
    }
    if (updateCheckBtn && updateMode.manualOnly) {
        updateCheckBtn.innerText = 'Open Releases';
    }
}

export function initUpdates() {
    if (window.basilisk?.update) {
        window.basilisk.update.onChecking(() => {
            if (updateStatus) updateStatus.innerText = 'Checking…';
        });

        window.basilisk.update.onAvailable((data) => {
            log('inf', `Update available: v${data.version}`);
            showBanner(`Basilisk v${data.version} is available`);
            updateDownloadBtn?.classList.remove('is-hidden');
            if (updateStatus) updateStatus.innerText = `v${data.version} available`;
            toast('inf', `Update available: v${data.version}`);
        });

        window.basilisk.update.onNotAvailable(() => {
            log('dim', 'Already on latest version.');
            if (updateStatus) {
                updateStatus.innerText = updateMode.manualOnly ? `${updateMode.displayLabel} · manual updates only` : 'Up to date ✓';
            }
        });

        window.basilisk.update.onProgress((data) => {
            setProgressDisplay(data.percent);
            if (updateText) updateText.innerText = `Downloading update… ${data.percent}%`;
        });

        window.basilisk.update.onDownloaded((data) => {
            log('ok', `Update v${data.version} downloaded. Ready to install.`);
            showBanner(`Basilisk v${data.version} is ready — restart to update`);
            updateDownloadBtn?.classList.add('is-hidden');
            updateInstallBtn?.classList.remove('is-hidden');
            updateProgressBar?.classList.add('is-hidden');
            if (updateStatus) updateStatus.innerText = `v${data.version} ready`;
            toast('ok', `Update v${data.version} ready! Click "Restart & Update" to install.`);
        });

        window.basilisk.update.onError((data) => {
            log('dim', `Update check: ${data.error}`);
            if (updateStatus) {
                updateStatus.innerText = updateMode.manualOnly ? `${updateMode.displayLabel} · manual updates only` : '';
            }
        });
    }

    updateDownloadBtn?.addEventListener('click', async () => {
        updateDownloadBtn.disabled = true;
        updateDownloadBtn.innerText = 'Downloading…';
        if (window.basilisk?.update) {
            const result = await window.basilisk.update.download();
            if (!result.success) {
                toast('error', `Download failed: ${result.error}`);
                updateDownloadBtn.disabled = false;
                updateDownloadBtn.innerText = 'Download';
            }
        }
    });

    updateInstallBtn?.addEventListener('click', async () => {
        if (window.basilisk?.update) {
            const result = await window.basilisk.update.install();
            if (result && result.success === false) {
                toast('error', result.error || 'Update install failed');
            }
        }
    });

    updateDismissBtn?.addEventListener('click', () => {
        updateBanner?.classList.add('hidden');
    });

    updateCheckBtn?.addEventListener('click', async () => {
        updateCheckBtn.disabled = true;
        updateCheckBtn.innerText = updateMode.manualOnly ? 'Opening…' : 'Checking…';
        try {
            if (updateMode.manualOnly || !window.basilisk?.update) {
                const result = await window.basilisk?.openExternal?.(RELEASES_URL);
                if (result && !result.success) {
                    toast('error', result.error || 'Failed to open releases');
                }
            } else {
                await window.basilisk.update.check();
            }
        } catch (e) {
            toast('error', `Update check failed: ${e.message}`);
        }
        updateCheckBtn.disabled = false;
        updateCheckBtn.innerText = updateMode.manualOnly ? 'Open Releases' : 'Check for Updates';
    });

    loadUpdateStatus();
    log('inf', 'Basilisk Desktop initialized.');
}
