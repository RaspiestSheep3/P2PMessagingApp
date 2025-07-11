// See the Electron documentation for details on how to use preload scripts:
// https://www.electronjs.org/docs/latest/tutorial/process-model#preload-scripts
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  navigateTo: (page) => ipcRenderer.send('navigate-to', page),
  closeApp: () => ipcRenderer.send('close-app')
});

//!TEMP - FOR TESTING MULTIPLE USERS
console.log("Preload process.argv:", process.argv);

const backendPortArg = process.argv.find(arg => arg.startsWith('--backendport='));
console.log(`backendPortArg : ${backendPortArg}`)
const backendPort = backendPortArg ? backendPortArg.split('=')[1] : '';
console.log("Preload sees backendPort:", backendPort);
contextBridge.exposeInMainWorld('myAPI', {
  backendPort: backendPort
});