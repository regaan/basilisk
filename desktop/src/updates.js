/**
 * Basilisk Desktop — Auto-Update Module
 * Update notifications, download, install, and manual check.
 */

const updateBanner = document.getElementById('update-banner');
const updateText = document.getElementById('update-banner-text');
const updateDownloadBtn = document.getElementById('btn-update-download');
const updateInstallBtn = document.getElementById('btn-update-install');
const updateDismissBtn = document.getElementById('btn-update-dismiss');
const updateProgressBar = document.getElementById('update-progress-bar');
const updateProgressFill = document.getElementById('update-progress-fill');
const updateStatus = document.getElementById('update-status');

function showBanner(text) {
    if (updateBanner) { updateBanner.classList.remove('hidden'); updateText.innerText = text; }
}

if (window.basilisk?.update) {
    window.basilisk.update.onChecking(() => {
        if (updateStatus) updateStatus.innerText = 'Checking…';
    });

    window.basilisk.update.onAvailable((data) => {
        log('inf', `Update available: v${data.version}`);
        showBanner(`Basilisk v${data.version} is available`);
        if (updateDownloadBtn) { updateDownloadBtn.style.display = 'inline-flex'; }
        if (updateStatus) updateStatus.innerText = `v${data.version} available`;
        toast('inf', `Update available: v${data.version}`);
    });

    window.basilisk.update.onNotAvailable((data) => {
        log('dim', `Already on latest version.`);
        if (updateStatus) updateStatus.innerText = 'Up to date ✓';
    });

    window.basilisk.update.onProgress((data) => {
        if (updateProgressBar) updateProgressBar.style.display = 'block';
        if (updateProgressFill) updateProgressFill.style.width = `${data.percent}%`;
        if (updateText) updateText.innerText = `Downloading update… ${data.percent}%`;
    });

    window.basilisk.update.onDownloaded((data) => {
        log('ok', `Update v${data.version} downloaded. Ready to install.`);
        showBanner(`Basilisk v${data.version} is ready — restart to update`);
        if (updateDownloadBtn) updateDownloadBtn.style.display = 'none';
        if (updateInstallBtn) updateInstallBtn.style.display = 'inline-flex';
        if (updateProgressBar) updateProgressBar.style.display = 'none';
        if (updateStatus) updateStatus.innerText = `v${data.version} ready`;
        toast('ok', `Update v${data.version} ready! Click "Restart & Update" to install.`);
    });

    window.basilisk.update.onError((data) => {
        log('dim', `Update check: ${data.error}`);
        if (updateStatus) updateStatus.innerText = '';
    });
}

updateDownloadBtn?.addEventListener('click', async () => {
    updateDownloadBtn.disabled = true;
    updateDownloadBtn.innerText = 'Downloading…';
    if (window.basilisk?.update) {
        const r = await window.basilisk.update.download();
        if (!r.success) { toast('error', `Download failed: ${r.error}`); updateDownloadBtn.disabled = false; updateDownloadBtn.innerText = 'Download'; }
    }
});

updateInstallBtn?.addEventListener('click', () => {
    if (window.basilisk?.update) window.basilisk.update.install();
});

updateDismissBtn?.addEventListener('click', () => {
    if (updateBanner) updateBanner.classList.add('hidden');
});

document.getElementById('btn-check-update')?.addEventListener('click', async () => {
    const btn = document.getElementById('btn-check-update');
    btn.disabled = true;
    btn.innerText = 'Checking…';
    try {
        if (window.basilisk?.update) {
            await window.basilisk.update.check();
        } else {
            if (window.basilisk?.openExternal) await window.basilisk.openExternal('https://github.com/regaan/basilisk/releases');
        }
    } catch (e) {
        toast('error', `Update check failed: ${e.message}`);
    }
    btn.disabled = false;
    btn.innerText = 'Check for Updates';
});
