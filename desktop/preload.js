const { contextBridge, ipcRenderer } = require('electron');

const WINDOW_CHANNELS = new Set(['window:minimize', 'window:maximize', 'window:close']);
const INVOKE_CHANNELS = new Set([
    'dialog:copyFile',
    'dialog:exportReport',
    'dialog:saveFile',
    'shell:openExternal',
    'update:check',
    'update:download',
    'update:install',
    'update:getStatus',
    'backend:request',
]);

function send(channel, ...args) {
    if (WINDOW_CHANNELS.has(channel)) {
        ipcRenderer.send(channel, ...args);
    }
}

function invoke(channel, ...args) {
    if (INVOKE_CHANNELS.has(channel)) {
        return ipcRenderer.invoke(channel, ...args);
    }
    return Promise.reject(new Error(`IPC channel not allowed: ${channel}`));
}

async function request(path, options = {}) {
    return invoke('backend:request', {
        path,
        method: options.method || 'GET',
        body: options.body ?? null,
    });
}

const basiliskApi = {
    send,
    invoke,
    request,

    onBackendLog: (cb) => ipcRenderer.on('backend-log', (_, msg) => cb(msg)),
    onBackendError: (cb) => ipcRenderer.on('backend-error', (_, msg) => cb(msg)),
    onBackendEvent: (cb) => ipcRenderer.on('backend:event', (_, msg) => cb(msg)),

    report: {
        export: async (sessionId, format) => {
            try {
                const data = await request(`/api/report/${sessionId}`, {
                    method: 'POST',
                    body: { format, open_browser: false },
                });
                if (!data.path) {
                    return { success: false, error: data.error || 'No report generated' };
                }
                const ext = format === 'html' ? 'html'
                    : format === 'sarif' ? 'sarif'
                    : format === 'markdown' ? 'md'
                    : format === 'pdf' ? 'pdf'
                    : 'json';
                return invoke('dialog:copyFile', {
                    sourcePath: data.path,
                    defaultName: `basilisk_report_${Date.now()}.${ext}`,
                    filters: [{ name: `${format.toUpperCase()} Report`, extensions: [ext] }],
                });
            } catch (e) {
                return { success: false, error: e.message };
            }
        },
    },

    apiKeys: {
        set: async (provider, key) => {
            try {
                return await request('/api/settings/apikey', {
                    method: 'POST',
                    body: { provider, key },
                });
            } catch (e) {
                return { success: false, error: e.message };
            }
        },
    },

    modules: {
        getMultiturn: () => request('/api/modules/multiturn'),
        getAll: () => request('/api/modules'),
    },

    evolution: {
        getOperators: () => request('/api/evolution/operators'),
    },

    openExternal: (url) => invoke('shell:openExternal', url),

    update: {
        check: () => invoke('update:check'),
        download: () => invoke('update:download'),
        install: () => invoke('update:install'),
        getStatus: () => invoke('update:getStatus'),
        onAvailable: (cb) => ipcRenderer.on('update:available', (_, data) => cb(data)),
        onNotAvailable: (cb) => ipcRenderer.on('update:not-available', (_, data) => cb(data)),
        onProgress: (cb) => ipcRenderer.on('update:progress', (_, data) => cb(data)),
        onDownloaded: (cb) => ipcRenderer.on('update:downloaded', (_, data) => cb(data)),
        onError: (cb) => ipcRenderer.on('update:error', (_, data) => cb(data)),
        onChecking: (cb) => ipcRenderer.on('update:checking', () => cb()),
    },
};

contextBridge.exposeInMainWorld('basilisk', basiliskApi);
contextBridge.exposeInMainWorld('api', basiliskApi);
