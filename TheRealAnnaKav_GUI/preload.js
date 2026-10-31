const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('annaKav', {
  getHashmap: () => ipcRenderer.invoke('annakav:getHashmap'),
  selectTarget: (mode) => ipcRenderer.invoke('annakav:selectTarget', mode),
  scanTargets: (payload) => ipcRenderer.invoke('annakav:scanTargets', payload),
  createDbSignature: (payload) => ipcRenderer.invoke('annakav:createDbSignature', payload),
  getSecurityStatus: () => ipcRenderer.invoke('annakav:getSecurityStatus'),
  onLog: (cb) => ipcRenderer.on('annakav:log', (_e, msg) => cb(msg))
});
