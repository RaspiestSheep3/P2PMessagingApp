const { app, BrowserWindow } = require('electron');
const path = require('node:path');

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require('electron-squirrel-startup')) {
  app.quit();
}

//!TEMP - FOR SETTING BACKEND PORT
const arg = process.argv.find(arg => arg.startsWith('--backendPort='));
const backendPort = arg ? parseInt(arg.split('=')[1], 10) : 0;
console.log(`Starting Electron with backendPort = ${backendPort}`);

const createWindow = () => {
  const iconPath = path.join(__dirname, 'icons', 'favicon.ico'); 

  console.debug(`ICON PATH : ${iconPath}`)

  // Create the browser window.
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    icon: iconPath,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // and load the index.html of the app.
  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  // Open the DevTools.
  mainWindow.webContents.openDevTools();
};

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(() => {
  createWindow();

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
var identifier = null;

async function GetDetails(){
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetDetails`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Details fetched:", data);
    identifier = data["identifier"]    

  } catch (error) {
      console.error("Fetch error:", error);
  }
}

async function GetSavedUsers(){
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetSavedUsers`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Saved Users fetched:", data);

  } catch (error) {
      console.error("Fetch error:", error);
  }
}

async function GetMessages(otherIdentifier){
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetMessages/${otherIdentifier}`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Messages fetched:", data);
  } catch (error) {
      console.error("Fetch error:", error);
  }
}

async function Init() {
  await GetDetails();
  console.debug("GOT DETAILS");
  await GetSavedUsers();
  console.debug("GOT SAVED USERS")
  await GetMessages("B")
  console.debug("GOT MESSAGES");
}

Init()