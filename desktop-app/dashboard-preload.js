const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kobaDesktop', {
  getAuthState: () => ipcRenderer.invoke('get-auth-state'),
  setAuthState: (state) => ipcRenderer.invoke('set-auth-state', state),
  clearAuthState: () => ipcRenderer.invoke('clear-auth-state'),
});
