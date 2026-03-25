const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');

function waitForFile(filePath, timeoutMs = 30000) {
    const started = Date.now();
    return new Promise((resolve, reject) => {
        const timer = setInterval(() => {
            if (fs.existsSync(filePath)) {
                clearInterval(timer);
                resolve(JSON.parse(fs.readFileSync(filePath, 'utf8')));
                return;
            }
            if (Date.now() - started > timeoutMs) {
                clearInterval(timer);
                reject(new Error(`Timed out waiting for ${filePath}`));
            }
        }, 250);
    });
}

function waitForSnapshot(child, filePath, timeoutMs = 30000) {
    const started = Date.now();
    let stdout = '';
    let stderr = '';
    let lastSnapshot = null;
    child.stdout?.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr?.on('data', (chunk) => { stderr += chunk.toString(); });

    return new Promise((resolve, reject) => {
        const timer = setInterval(() => {
            if (fs.existsSync(filePath)) {
                lastSnapshot = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                const isTerminal = lastSnapshot.uiReady || ['backend_timeout', 'ui_error', 'backend_error', 'startup_error'].includes(lastSnapshot.stage);
                if (isTerminal) {
                    clearInterval(timer);
                    resolve(lastSnapshot);
                    return;
                }
            }
            if (Date.now() - started > timeoutMs) {
                clearInterval(timer);
                reject(new Error(`Timed out waiting for terminal E2E snapshot ${filePath}\nlast snapshot:\n${JSON.stringify(lastSnapshot, null, 2)}\nstdout:\n${stdout}\nstderr:\n${stderr}`));
            }
        }, 250);

        child.once('exit', (code, signal) => {
            if (!lastSnapshot || !lastSnapshot.uiReady) {
                clearInterval(timer);
                reject(new Error(`Electron exited before terminal UI-ready snapshot (code=${code}, signal=${signal})\nlast snapshot:\n${JSON.stringify(lastSnapshot, null, 2)}\nstdout:\n${stdout}\nstderr:\n${stderr}`));
            }
        });
    });
}

test('electron desktop boots backend and reaches renderer-ready state', async () => {
    const electronBinary = path.join(__dirname, '..', 'node_modules', '.bin', process.platform === 'win32' ? 'electron.cmd' : 'electron');
    if (!fs.existsSync(electronBinary)) {
        test.skip('Electron binary not installed in desktop/node_modules');
        return;
    }

    const outFile = path.join(os.tmpdir(), `basilisk-e2e-${Date.now()}.json`);
    const childEnv = { ...process.env };
    delete childEnv.ELECTRON_RUN_AS_NODE;
    const child = spawn(electronBinary, ['--no-sandbox', '--disable-setuid-sandbox', '.'], {
        cwd: path.join(__dirname, '..'),
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
            ...childEnv,
            BASILISK_E2E: '1',
            BASILISK_E2E_AUTOEXIT: '1',
            BASILISK_E2E_OUT: outFile,
        },
    });

    try {
        const data = await waitForSnapshot(child, outFile, 45000);
        assert.equal(data.backendReady, true);
        assert.equal(data.uiReady, true);
        assert.equal(data.stage, 'ui_ready');
        assert.ok(data.backendPort);
        assert.ok(data.tabCount >= 10);
        assert.equal(data.hasRetentionInput, true);
        assert.ok(data.activeView);
        assert.match(data.secretStoreStatus, /Storage:/);
        assert.equal(data.hasLegacyTokenGetter, false);
        assert.match(data.updateTrust, /Build|Community|Vendor/i);
        assert.ok(data.liveFindingsCount >= 1);
        assert.ok(data.sessionRows >= 1);
        assert.equal(data.cleanAuditVisible, true);
        assert.equal(data.reportExported, true);
        assert.ok(data.reportOptions >= 2);
        assert.equal(data.stopWorked, true);
        assert.equal(data.logCapturedCompletion, true);
    } finally {
        child.kill('SIGTERM');
        fs.rmSync(outFile, { force: true });
    }
});
