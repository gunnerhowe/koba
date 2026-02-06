const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('koba', {
  getStatus: () => ipcRenderer.invoke('get-status'),
  startKoba: () => ipcRenderer.invoke('start-koba'),
  stopKoba: () => ipcRenderer.invoke('stop-koba'),
  openDashboard: () => ipcRenderer.invoke('open-dashboard'),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  setSettings: (settings) => ipcRenderer.invoke('set-settings', settings),
  onStatusUpdate: (callback) => {
    ipcRenderer.removeAllListeners('status-update');
    ipcRenderer.on('status-update', (event, status) => callback(status));
  },

  // Update system
  checkForUpdate: () => ipcRenderer.invoke('check-for-update'),
  applyUpdate: () => ipcRenderer.invoke('apply-update'),
  dismissUpdate: () => ipcRenderer.invoke('dismiss-update'),
  getUpdateStatus: () => ipcRenderer.invoke('get-update-status'),
  onUpdateChecking: (callback) => {
    ipcRenderer.removeAllListeners('update-checking');
    ipcRenderer.on('update-checking', () => callback());
  },
  onUpdateAvailable: (callback) => {
    ipcRenderer.removeAllListeners('update-available');
    ipcRenderer.on('update-available', (event, info) => callback(info));
  },
  onUpdateNotAvailable: (callback) => {
    ipcRenderer.removeAllListeners('update-not-available');
    ipcRenderer.on('update-not-available', () => callback());
  },
  onUpdateProgress: (callback) => {
    ipcRenderer.removeAllListeners('update-progress');
    ipcRenderer.on('update-progress', (event, data) => callback(data));
  },
  onUpdateApplying: (callback) => {
    ipcRenderer.removeAllListeners('update-applying');
    ipcRenderer.on('update-applying', () => callback());
  },
  onUpdateApplied: (callback) => {
    ipcRenderer.removeAllListeners('update-applied');
    ipcRenderer.on('update-applied', () => callback());
  },
  onUpdateError: (callback) => {
    ipcRenderer.removeAllListeners('update-error');
    ipcRenderer.on('update-error', (event, msg) => callback(msg));
  },
});
