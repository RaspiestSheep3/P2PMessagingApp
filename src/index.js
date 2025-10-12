const { app, BrowserWindow } = require('electron');
const path = require('node:path');
const { spawn } = require('child_process');
const net = require('net');

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require('electron-squirrel-startup')) {
  app.quit();
}

let mainWindow;
//const backendPort = 5000;

// Extract backendPort from process.argv
const backendPortArg = process.argv.find(arg => arg.startsWith('backendPort='));
backendPort = backendPortArg ? backendPortArg.split('=')[1] : 5000;


console.log("Index is passing backendPort:", backendPort);

const createWindow = () => {
  const iconPath = path.join(__dirname, 'icons', 'favicon.ico'); 

  console.debug(`ICON PATH : ${iconPath}`)


  // Create the browser window.
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    icon: iconPath,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),

      contextIsolation: true, 
      nodeIntegration: false, 

      additionalArguments: [`--backendPort=${backendPort}`]
    },
  });

  // and load the login.html of the app.
  mainWindow.loadURL(`http://localhost:${Number(backendPort)}/api/LoadPage/login.html`);

  // Open the DevTools.
  mainWindow.webContents.openDevTools();
};

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.

function waitForPort(port, host = '127.0.0.1', timeout = 30000) {
    return new Promise((resolve, reject) => {
        const start = Date.now();
        const interval = setInterval(() => {
            const socket = new net.Socket();
            socket.setTimeout(1000);
            socket.on('connect', () => { clearInterval(interval); socket.destroy(); resolve(); });
            socket.on('error', () => socket.destroy());
            socket.on('timeout', () => socket.destroy());
            socket.connect(port, host);

            if (Date.now() - start > timeout) {
                clearInterval(interval);
                reject('Timeout waiting for backend');
            }
        }, 200); // poll every 200ms
    });
}

app.whenReady().then(() => {
  //createWindow();

  const backendPath = path.join(__dirname, "..", "Peer.py"); 
  const backend = spawn("python", [backendPath, backendPort]);
  backend.stdout.on('data', data => console.log(`Backend: ${data}`));
  backend.stderr.on('data', data => console.log(`Backend alert: ${data}`));
  backend.on('error', err => console.error('Failed to start backend:', err));
  
  setTimeout(() => {
      waitForPort(5000)
          .then(() => {
              console.log('Backend ready');
              createWindow();
          })
          .catch(err => {
              console.error('Backend failed to start:', err);
              app.quit();
          });
  }, 1000);

  // On OS X it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and import them here.
const { ipcMain } = require('electron');
const { type } = require('node:os');

ipcMain.on('navigate-to', (event, page) => {
  mainWindow.loadURL(`http://localhost:${Number(backendPort)}/api/LoadPage/${page}`);
});

let isQuitting = false;
ipcMain.on('close-app', () => {
  isQuitting = true;
  app.quit();
});

app.on('before-quit', async (event) => {
  if (!isQuitting) {
    event.preventDefault();

    try {
      await fetch(`http://127.0.0.1:${backendPort}/api/Post/Shutdown`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ shutdown: 'True' })
      });
    } catch (err) {
      console.error('Shutdown request failed:', err);
    }

    isQuitting = true;
    app.quit();
  }
});