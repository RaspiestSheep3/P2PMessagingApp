let identifier = null;
let savedUsers = null;
let savedUsersMap = null;
let onlineUsers = null;
let messages = null;
let themes = null;
let currentTheme = null;
let publicKey = null;
let displayName = null;
let targetedUserIdentifier = null;
let sendNotifications = false;
let maxMessageLength = 0;
let use12hFormat = false;
let activeSessions = [];
let dateFormat = null;
let timeoutTime = "";
let displayTime = "";

let currentlySendingSessionChange = false;
//Consts 
const stylesheet = document.documentElement.style;
const now = new Date();
const maxThemeButtonsInRow = 4; 
const notificationMaxLengthChars = 37;
const onlineDisplayDict = {
  true : "🟢",
  false : "🔴"
};
const imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tif', 'tiff', 'ico', 'svg', 'heic'];
const dateFormatOptions = [
  "DD/MM/YYYY", "DD/MM/YY",
  "MM/DD/YYYY", "MM/DD/YY",
  "YYYY/MM/DD", "YY/MM/DD",
  "DD-MM-YYYY", "DD-MM-YY",
  "MM-DD-YYYY", "MM-DD-YY",
  "YYYY-MM-DD", "YY-MM-DD"
]

//!TEMP - FOR TESTING MULTIPLE USERS
const backendPort = window.myAPI.backendPort;
console.log(`RUNNING ON BACKEND PORT ${backendPort}`);

async function GetDetails() {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetDetails`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Details fetched:", data);
    identifier = data["identifier"];   
    currentTheme = data["theme"] ;
    publicKey = data["publicKey"];
    displayName = data["displayName"];
    maxMessageLength = data["maxMessageLength"];
    sendNotifications = data["sendNotifications"].toLowerCase() === "true";
    use12hFormat = data["use12hFormat"].toLowerCase() === "true";
    dateFormat = data["dateFormat"];

  } catch (error) {
      console.error("Fetch error:", error);
  }
}

function SetSidebar() {
  const messageBox = document.getElementById("messagingInputField");

  //Chat page
  document.getElementById('chatIcon').addEventListener('click', () => {
      window.electronAPI.navigateTo('index.html');
  });

  //Settings page
  document.getElementById('settingsIcon').addEventListener('click', async () => {
    //Saving drafts
    if(page==="chat" && targetedUserIdentifier != null) await SaveDraft(targetedUserIdentifier, messageBox.value);
    window.electronAPI.navigateTo('settings.html');
  });

  //Key Display page
  document.getElementById('keyIcon').addEventListener('click', async () => {
    if(page==="chat" && targetedUserIdentifier != null) await SaveDraft(targetedUserIdentifier, messageBox.value);
    window.electronAPI.navigateTo('keydisplay.html');
  });

  //Shutdown
  document.getElementById("shutdownIcon").addEventListener("dblclick", async () => {
    if(page==="chat" && targetedUserIdentifier != null) await SaveDraft(targetedUserIdentifier, messageBox.value);
    console.log('Double-click detected!');
    Shutdown();
  });
}

async function Shutdown() {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/Shutdown`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({"shutdown" : "True"})
    });

    const data = await response.json();
    console.log("POST Response in Shutdown:", data);
    window.electronAPI.closeApp();
    
  } catch (error) {
    console.error("Error posting data:", error);
  }
}

async function GetSavedUsers() {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetSavedUsers`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Saved Users fetched:", data);
    console.log(`Users : ${data.users} ${typeof(data.users)}, Online : ${data.onlineUsers}`);

    return data;
  } catch (error) {
      console.error("Fetch error:", error);
  }
}

async function GetMessages(otherIdentifier, amount, sort, reversed) {
  try {
    console.log(`FETCHING IN GET MESSAGES : http://127.0.0.1:${backendPort}/api/GetMessages/${otherIdentifier}?amount=${amount}&sort=${sort}&reversed=${reversed}`);
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetMessages/${otherIdentifier}?amount=${amount}&sort=${sort}&reversed=${reversed}`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    console.log("Messages fetched:", data);

    return data;
  } catch (error) {
      console.error("Fetch error:", error);
  }
}

async function GetDisplayMessages(id, chatID, banner, amount=0, sort="asc", reversed="false") {
  console.debug(`DISPLAYING MESSAGES FOR ${id}`);
  messages = await GetMessages(id, amount, sort, reversed);
  console.debug("GOT MESSAGES");
  DisplayMessages(messages, id, chatID, banner);
  console.debug("DISPLAYING MESSAGES");
}

function DisplaySetUsers(id, chatID, banner="", amount = 0, sort = "asc" ,reversed = "false", sessionButton=false) {
  let chatListUL = document.getElementById(id);
  chatListUL.innerHTML = "";

  let savedUsersLi = [];

  savedUsers.forEach(savedUser => {
    const li = document.createElement("li");
    li.className = "displayText chatlistElement underlineFade";
    li.id = savedUser[0]; 
    li.textContent = `${savedUser[1]} ${onlineDisplayDict[onlineUsers.includes(li.id)]}`;
    li.addEventListener("click",async () => {
      //Saving old draft
      const messageBox = document.getElementById("messagingInputField");
      if(messageBox != null && messageBox.value != "" && messageBox.value != null && targetedUserIdentifier != null) await SaveDraft(targetedUserIdentifier, messageBox.value);

      targetedUserIdentifier = li.id;
      GetDisplayMessages(li.id, chatID, banner, amount, sort, reversed);
      if(messageBox != null) messageBox.value = (await GetDraft(li.id))["draft"];
      
      if(sessionButton) SetSessionButton(li.id);
    });
    chatListUL.appendChild(li);
    savedUsersLi.push(li);
  });

  return savedUsersLi;
}

async function GetDraft(otherIdentifier) {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetDraft/${otherIdentifier}`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    console.log("Draft Fetched", data);

    return data;
  } catch (error) {
      console.error("Fetch error:", error);
  }
}

async function SaveDraft(otherIdentifier, draft) {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/SaveDraft`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({"otherIdentifier" : otherIdentifier, "draft" : draft})
    });

    const data = await response.json();
    console.log("POST Response in SaveDraft:", data);
    
  } catch (error) {
    console.error("Error posting data in SaveDraft:", error);
  }
}

async function SendFile(dataToSend) {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/SendFile`, {
        method: 'POST',
        body: dataToSend
    });

    const data = await response.json();
    console.log("POST Response in SendFile:", data);
    
  } catch (error) {
    console.error("Error posting data:", error);
  }
  const messages = await new Promise((resolve, reject) => {
    setTimeout(async () => {
      try {
        resolve(await GetMessages(targetedUserIdentifier, 0, "asc", "false"));
      } catch (err) {
        reject(err);
      }
    }, 300);
  });
  await DisplayMessages(messages, targetedUserIdentifier, "chat", "contactBannerText");
}

async function DownloadFile(filePath, extension, outputFolder, filename){
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/DownloadFile`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({"filePath" : filePath, "extension" : extension, "outputFolder" : outputFolder, "filename" : filename})
    });

    const data = await response.json();
    console.log("POST Response in DownloadFile:", data);
    
  } catch (error) {
    console.error("Error posting data:", error);
  }
}

async function DeleteMessage(messageTimestamp, messageRandomisation, otherIdentifier, deleteType) {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/DeleteMessage`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({"timestamp" : messageTimestamp, "messageRandomisation" : messageRandomisation, "otherIdentifier" : otherIdentifier, "deleteType" : deleteType})
    });

    const data = await response.json();
    console.log("POST Response in DownloadFile:", data);
    if(data.status == "success"){
      messages.splice(messages.indexOf(data.deletedRow), 1);
      console.log("New Messages in DeleteMessage : ", messages)
      DisplayMessages(messages, targetedUserIdentifier, "chat", "contactBannerText")
    }
  } catch (error) {
    console.error("Error posting data:", error);
  }

  
}

function DisplayMessages(messagesToDisplay, messagerIdentifier, chatID, banner="") {
  let chat = document.getElementById(chatID);
  chat.innerHTML = "";
  let lastProcessedTime = "0000-00-00"

  messagesToDisplay.forEach(messageToDisplay => {
      //Setting the timestamp things
      let timestampDate = messageToDisplay.timestamp.slice(0, lastProcessedTime.length);  
      if(timestampDate > lastProcessedTime){
        const timestampDateSplit = timestampDate.split("-");
        let timestampDisplay = "";
        console.log(`Date Format : ${dateFormat}`);
        
        let containsDashes = null;
        if(dateFormat.includes("-")){
          dateFormat = dateFormat.replaceAll("-", "/");
           containsDashes = true;
        }
        else  containsDashes = false;
        switch (dateFormat) {
          case "DD/MM/YYYY": timestampDisplay = `${timestampDateSplit[2]}/${timestampDateSplit[1]}/${timestampDateSplit[0]}`; break;
          case "DD/MM/YY": timestampDisplay = `${timestampDateSplit[2]}/${timestampDateSplit[1]}/${timestampDateSplit[0].slice(2,4)}`; break;
          case "DD/MM/YYYY": timestampDisplay = `${timestampDateSplit[1]}/${timestampDateSplit[2]}/${timestampDateSplit[0]}`; break;
          case "MM/DD/YY": timestampDisplay = `${timestampDateSplit[1]}/${timestampDateSplit[2]}/${timestampDateSplit[0].slice(2,4)}`; break;
          case "YYYY/MM/DD": timestampDisplay = `${timestampDateSplit[0]}/${timestampDateSplit[1]}/${timestampDateSplit[2]}`; break;
          case "YY/MM/DD": timestampDisplay = `${timestampDateSplit[0].slice(2,4)}/${timestampDateSplit[1]}/${timestampDateSplit[2]}`; break;
        }

        if(containsDashes){
          timestampDisplay = timestampDisplay.replaceAll("/", "-");
          dateFormat = dateFormat.replaceAll("/", "-");
        }
        
        console.log(`timestampDisplay : ${timestampDisplay} ${dateFormat} ${containsDashes}`);
        chat.innerHTML += `<div class="chatTimestamp displayText">${timestampDisplay}</div>`;
        lastProcessedTime = timestampDate;
      }

      const div = document.createElement("div");
      div.className = "displayText message";

      if(messageToDisplay.identifier === identifier){
        div.classList.add("messageOutgoing");
        div.addEventListener("mousedown", e => {
          if(e.button === 2){
            document.querySelectorAll(".deleteMessageButton").forEach(element => element.style.display = "none");
            document.getElementById(`delAll|${messageToDisplay.timestamp}|${messageToDisplay.messageRandomisation}`).style.display = "inline-block";
            document.getElementById(`delMe|${messageToDisplay.timestamp}|${messageToDisplay.messageRandomisation}`).style.display = "inline-block";
          }
        });
      }
      else div.classList.add("messsageIncoming");
      
      console.debug(`MessageToDisplay :`, messageToDisplay);
      let messageTimestampArray = (messageToDisplay.timestamp.split(" ")[1]).split("-");
      console.debug(`Message timestamp array: ${messageTimestampArray}`);

      let ending = "";
      if(use12hFormat){
        if(Number(messageTimestampArray[0]) >= 12){ 
          ending = "PM";
          if(Number(messageTimestampArray[0]) > 13) messageTimestampArray[0] = String(Number(messageTimestampArray[0] - 12));
        }
        else ending = "AM";
      }
      let messageTimestamp = messageTimestampArray[0].padStart(2, '0') + ":" + messageTimestampArray[1].padStart(2, '0') + ending;
      if(messageToDisplay.type === "message"){
        div.innerHTML = messageToDisplay.message.replaceAll("\n", "<br>");
      }
      else if(messageToDisplay.type === "file"){
        if(imageExtensions.includes(messageToDisplay.extension)) {
          div.innerHTML = `<img src="/api/GetFileData/${messageToDisplay.extension}/${messageToDisplay.filePath}?shouldCrop=True" alt="Photo">`
          div.addEventListener("click", () => {
            if(page === "chat"){
              console.log("Image Clicked!");
              document.querySelector(".chat").style.display = "none";
              const imageViewer =  document.getElementById("imageViewer");
              imageViewer.style.display = "flex";
              imageViewer.innerHTML = `<button class="displayText button underlineFade" id="imageViewerReturnToMessages">Return To Chat</button>`
              imageViewer.innerHTML += `<button class="displayText button underlineFade" id="imageViewerDownload">Download File</button>`
              imageViewer.innerHTML += `<img src="/api/GetFileData/${messageToDisplay.extension}/${messageToDisplay.filePath}?shouldResize=True&maxHeight=512&maxWidth=1024" alt="Photo">`
              document.getElementById("imageViewerReturnToMessages").addEventListener("click", () => {
                document.getElementById("imageViewer").style.display = "none";
                document.querySelector(".chat").style.display = "flex";
              });
              document.getElementById("imageViewerDownload").addEventListener("click", () => {
                DownloadFile(messageToDisplay.filePath, messageToDisplay.extension, "downloads", messageToDisplay.userFilename)
              });
            }
          });
        } 
        else {
          div.classList.add("underlineFade");
          div.style.wordBreak = "break-all";
          div.innerHTML = `📄${messageToDisplay.userFilename.replaceAll("\n", "<br>")}.${messageToDisplay.extension}`;
          div.style.cursor = "pointer";
          div.addEventListener("click", () => {
            DownloadFile(messageToDisplay.filePath, messageToDisplay.extension, "downloads", messageToDisplay.userFilename)
          });
        }
      }
      div.innerHTML = div.innerHTML + `<div class="timestamp">${messageTimestamp}</div>`;
      div.innerHTML += `<button class="displayText button underlineFade deleteMessageButton delAll" id="delAll|${messageToDisplay.timestamp}|${messageToDisplay.messageRandomisation}">Del All</button>`
      div.innerHTML += `<button class="displayText button underlineFade deleteMessageButton delMe" id="delMe|${messageToDisplay.timestamp}|${messageToDisplay.messageRandomisation}">Del Me </button>`
      chat.appendChild(div);
      const delAllButton = document.getElementById(`delAll|${messageToDisplay.timestamp}|${messageToDisplay.messageRandomisation}`);
      const delMeButton = document.getElementById(`delMe|${messageToDisplay.timestamp}|${messageToDisplay.messageRandomisation}`);
      delAllButton.style.display = "none";
      delMeButton.style.display = "none";
      delAllButton.addEventListener("click", () => DeleteMessage(messageToDisplay.timestamp, messageToDisplay.messageRandomisation, targetedUserIdentifier, "all"));
      delMeButton.addEventListener("click", () => DeleteMessage(messageToDisplay.timestamp, messageToDisplay.messageRandomisation, targetedUserIdentifier, "me"));
    });

  if(banner !== "") {
    let messageLabel = document.getElementById(banner);
    console.log(`Messanger Identifier in DisplayMessages : ${messagerIdentifier} ${onlineUsers}`);
    messageLabel.textContent = `${savedUsersMap.get(messagerIdentifier)} ${onlineDisplayDict[onlineUsers.includes(messagerIdentifier)]}`;
  }

  if( page==="chat"){
    document.getElementById("uploadFileButton").addEventListener("click", () => {
      if(!activeSessions.includes(targetedUserIdentifier)) return;
      document.getElementById("fileInput").click();
    });

    document.getElementById("fileInput").addEventListener("change", (event) => {
      const file = event.target.files[0];
      console.log("Recieved new file");
      if (!file) return;

      const formData = new FormData();

      const extension = file.name.split(".").pop();
      const filename = file.name.replace(`.${extension}`, "");
      console.debug(`extension ${extension} filename ${filename}`);
      formData.append("file", file);
      formData.append("extension", extension);
      formData.append("filename", filename);
      formData.append("otherIdentifier", messagerIdentifier);

      SendFile(formData);
    });
  } 
}

async function GetThemes() {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetThemes`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Themes fetched:", data);

    return data
  } catch (error) {
      console.error("Fetch error:", error);
  }
}

function UpdateCSSTheme(newTheme) {
  //Updating CSS
  let themeValues = themes[newTheme];
  console.log(`THEME VALUES : ${themeValues}, ${newTheme}`);
  stylesheet.setProperty("--backgroundColour", themeValues["background"]);
  stylesheet.setProperty("--mainColour", themeValues["main"]);
  stylesheet.setProperty("--accentColour", themeValues["accent"]);
}

async function SetSetting(key, newValue) {
 try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/SetSetting`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({"key" : key, "value" : newValue})
    });

    const data = await response.json();
    console.log("POST Response in SetSetting:", data);
    
  } catch (error) {
    console.error("Error posting data:", error);
  }

  if(key === "theme") UpdateCSSTheme(newValue);
}

function SetThemeButtons() {
  //Goal is to make an adaptable system - i / a user can simply add more stuff to the Themes.json 
  let themeButtonsArea = document.getElementById("themeButtons");
  for(var i = 0; i < Math.ceil(Object.keys(themes).length / maxThemeButtonsInRow); i++) {
    let themeRow = document.createElement("div");
    themeRow.className = "themeButtonRow";
    themeButtonsSlice = Object.keys(themes).slice(i*maxThemeButtonsInRow, (i+1) * maxThemeButtonsInRow);
    themeButtonsSlice.forEach(themeButtonData => {
      let themeButton = document.createElement("button");
      themeButton.className = "displayText button themeButton underlineFade";
      themeButton.id = themeButtonData;
      themeButton.textContent = themeButtonData;
      themeButton.addEventListener("click", () => {
        console.log(`${themeButton.id} SELECTED`);
        SetSetting("theme", themeButton.id);
      });
      themeRow.appendChild(themeButton);
      console.debug(themeButtonData);
    });
    
    themeButtonsArea.appendChild(themeRow);
  }
}

function DisplayKeyData() {
  document.getElementById("selfIdentifierDisplay").textContent = `Identifier : ${identifier}`;
  document.getElementById("selfDisplayNameDisplay").textContent = `Display Name : ${displayName}`;
  document.getElementById("selfKeyDisplay").textContent = `Public Key : ${publicKey}`;
}

async function DisplayOtherUserDetails(id) {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetDetailsOfOtherUser/${id}`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Other User Details fetched:", data);

    document.getElementById("otherUserOverviewDisplayName").textContent = `Display Name : ${data.displayName}`;
    document.getElementById("otherUserOverviewIdentifier").textContent = `Identifier : ${data.identifier}`;
    document.getElementById("otherUserOverviewPublicKey").textContent = `Public Key : ${data.publicKey}`;
    
    //Fetching messages for display
    const messagesToDisplay = await GetMessages(id, 3, "desc", "true");
    DisplayMessages(messagesToDisplay, id, "otherUserOverviewRecentMessages");


  } catch (error) {
    console.error("Fetch error:", error);
  }
}

function UserSearchBar(ul, searchBar) {
  searchBar.addEventListener("input", () => {
    let filter = searchBar.value.toUpperCase();
    let liList = ul.getElementsByTagName('li');
    if(filter.trim() !== ""){
      for (let i = 0; i < liList.length; i++) {
        if (liList[i].textContent.toUpperCase().indexOf(filter) > -1) {
          liList[i].style.display = "";
        } else {
          liList[i].style.display = "none";
        }
      }
    }
    else {
      for (let i = 0; i < liList.length; i++) {
        liList[i].style.display = "";
      }
    }
  });
}

async function SendMessage(messageBox, otherUserIdentifier, timeout, displayTime) {
  const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/SendMessageToUser/${otherUserIdentifier}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({"message" : messageBox.value, "timeout" : timeout, "displayTime" : displayTime})
    });
  console.log(response, "in SendMessage");

  SaveDraft(otherUserIdentifier, "");

  const pad = (n) => n.toString().padStart(2, '0');
  const timestamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;
  const messages = await new Promise((resolve, reject) => {
    setTimeout(async () => {
      try {
        resolve(await GetMessages(targetedUserIdentifier, 0, "asc", "false"));
      } catch (err) {
        reject(err);
      }
    }, 300);
  });
  await DisplayMessages(messages, targetedUserIdentifier, "chat", "contactBannerText");

  messageBox.value = "";
}

function FormatTimeSettings(messageTimeoutText, displayTimeText) {
  //Formatting
  let messageTimeoutObject = {
    "days" : 0,
    "hours" : 0,
    "minutes" : 0,
    "seconds" : 0
  };

  let displayTimeObject = {
    "days" : 0,
    "hours" : 0,
    "minutes" : 0,
    "seconds" : 0
  };

  const matchesTimeout = messageTimeoutText.match(/\d+[dhms]/gi) || [];
  const matchesDisplayTime = displayTimeText.match(/\d+[dhms]/gi) || [];
  matchesTimeout.forEach(element => {
    if (element.includes("d")) {
      messageTimeoutObject.days = Number(element.replace("d", ""));
    } else if (element.includes("h")) {
      messageTimeoutObject.hours = Number(element.replace("h", ""));
    } else if (element.includes("m")) {
      messageTimeoutObject.minutes = Number(element.replace("m", ""));
    } else if (element.includes("s")) {
      messageTimeoutObject.seconds = Number(element.replace("s", ""));
    }
  });
  matchesDisplayTime.forEach(element => {
    if (element.includes("d")) {
      displayTimeObject.days = Number(element.replace("d", ""));
    } else if (element.includes("h")) {
      displayTimeObject.hours = Number(element.replace("h", ""));
    } else if (element.includes("m")) {
      displayTimeObject.minutes = Number(element.replace("m", ""));
    } else if (element.includes("s")) {
      displayTimeObject.seconds = Number(element.replace("s", ""));
    }
  });

  return [messageTimeoutObject, displayTimeObject];
}

function SetupMessenger() {
  const messageBox = document.getElementById("messagingInputField");
  const messageSendButton = document.getElementById("sendMessageButton");
  const charCount = document.getElementById("charCount");

  messageBox.addEventListener("input", () => {
    if (messageBox.value.length > maxMessageLength) messageBox.value = messageBox.value.slice(0, maxMessageLength);
    //console.debug(`Current Length of Message : ${messageBox.value.length}/${maxMessageLength}`);
    charCount.textContent = `${messageBox.value.length}/${maxMessageLength}`;
  })

  messageSendButton.addEventListener("click", () => {
    if(!activeSessions.includes(targetedUserIdentifier)) return;
    if(messageBox.value.trim() === "") return;

    //Doing checks on the message settings
    const messageTimeoutText = document.getElementById("setTimeoutSettingsInput").value.trim();
    const displayTimeText = document.getElementById("setDisplayTimeSettingsInput").value.trim();

    const pattern = /^(\d+d)?(\s?\d+h)?(\s?\d+m)?(\s?\d+s)?$/i; //Regex sorcery to make sure the input is valid
    
    console.debug("Doing the regex check");
    if(messageTimeoutText.trim() !== "" && !pattern.test(messageTimeoutText)) return;
    if(displayTimeText.trim() !== "" && !pattern.test(displayTimeText)) return;
    console.debug("Passed the regex check");

    const [messageTimeoutObject, displayTimeObject] = FormatTimeSettings(messageTimeoutText, displayTimeText);

    charCount.textContent = `0/${maxMessageLength}`;
    SendMessage(messageBox, targetedUserIdentifier, messageTimeoutObject, displayTimeObject);
  });
}

function SetupSettingButtons() { 
  SetThemeButtons();
  console.log("SET THEME BUTTONS IN SetupSettingButtons");
  
  //Setting notification buttons
  const switchInput = document.querySelector('#notificationSwitchButton input[type="checkbox"]');
  switchInput.checked = sendNotifications;

  switchInput.addEventListener('change', (event) => {
    sendNotifications = event.target.checked;
    SetSetting("sendNotifications", String(sendNotifications));
  });

  //Setting 12h format buttons
  const hourFormatInput = document.querySelector('#hourFormatSwitchButton input[type="checkbox"]');
  hourFormatInput.checked = use12hFormat;

  hourFormatInput.addEventListener('change', (event) => {
    use12hFormat = event.target.checked;
    SetSetting("use12hFormat", String(use12hFormat));
  });

  //Setting Date Format buttons
  const dateFormatButton = document.getElementById("dateFormatDropdownButton");
  dateFormatButton.textContent = dateFormat;
  const dropdownContent = document.getElementById("dateFormatDropdown");
  dropdownContent.innerHTML = "";
  dateFormatOptions.forEach(format => {
    const div = document.createElement("div");
    div.addEventListener("click", () => {
      const associatedFormat = div.getAttribute("data-format");
      console.log(associatedFormat);
      dateFormat = associatedFormat;
      dateFormatButton.textContent = associatedFormat;
      SetSetting("dateFormat", associatedFormat);
      dropdownContent.style.display = "none";
    });
    div.className = "underlineFade displayText dropdownElement"
    div.dataset.format = format;
    div.textContent = format;
    dropdownContent.appendChild(div);
    
  });
  
  let dateFormatButtonActive = false;
  dateFormatButton.addEventListener("click", () => {
    console.log("clicked");
    if(dateFormatButtonActive){
      dropdownContent.style.display = "none";
      dateFormatButtonActive = false
    }
    else{
      dropdownContent.style.display = "block";
      dateFormatButtonActive = true;
    }
  });
}

async function ChangeSession(otherUserIdentifier, type){
  const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/ChangeSession`, {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({"identifier" : otherUserIdentifier, "type" : type})
  });
  console.log("Response in ChangeSession :", response);
  //SetSessionButton(otherUserIdentifier);
}

function SetSessionButton(otherUserIdentifier) {
  const buttonElement = document.getElementById("StartSessionButton");
  console.log("Active sessions in SetSessionButton :", activeSessions);
  if(activeSessions.includes(otherUserIdentifier)) buttonElement.textContent = "End Session";
  else buttonElement.textContent = "Start Session";
  buttonElement.addEventListener("click", async () => {
    if(currentlySendingSessionChange) return;

    if(activeSessions.includes(otherUserIdentifier)){
      console.debug("Closing session");
      activeSessions.splice(activeSessions.indexOf(otherUserIdentifier), 1);
      console.debug("New active sessions:", activeSessions);
      currentlySendingSessionChange = true;
      await ChangeSession(otherUserIdentifier, "end");
      currentlySendingSessionChange = false;
      buttonElement.textContent = "Start Session";
    }
    else {
      console.debug("Starting session");
      activeSessions.push(otherUserIdentifier);
      currentlySendingSessionChange = true;
      await ChangeSession(otherUserIdentifier, "start");
      currentlySendingSessionChange = false;
      buttonElement.textContent = "End Session";
    }
  });
}

async function SendNewUserRequest(host, port) {
  const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/AddNewUser`, {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({"host" : host.value, "port" : port.value})
  });
  host.value = "";
  port.value = "";
  console.log(response);

  let savedUsersObject = (await GetSavedUsers())
  savedUsers = savedUsersObject.users;
  savedUsersMap = new Map(savedUsers);
  onlineUsers = savedUsersObject.onlineUsers;
  console.debug("GOT SAVED USERS in SendNewUserRequest");
  DisplaySetUsers("chatlistUL", "chat", "contactBannerText",0,"asc","false",true);
  console.debug("DISPLAYED SAVED USERS in SendNewUserRequest")

}

function SetAddUserButton(){
  const addUserButton = document.getElementById("AddUserButton");
  const hostInput = document.getElementById("addUserHostInput");
  const portInput = document.getElementById("addUserPortInput");

  addUserButton.addEventListener("click", () => {
    console.log("Adding User");
    if((hostInput.value.trim() != "") && (portInput.value.trim() != "") && (/^-?\d+$/.test(portInput.value.trim()))){
      SendNewUserRequest(hostInput, portInput);
    }
  });
}

async function GetSessions(){
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetOpenSessions`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Open sessions :", data);
    return Object.keys(data).filter(key => data[key]);

  } catch (error) {
    console.error("Fetch error:", error);
  }
}

function SetMessageButtons(){
  const messageButtons = document.querySelectorAll(".messageSettingButton");
  messageButtons.forEach(button => {
    button.addEventListener("click", () => {
      if(button.classList.contains("inverseAccent")){
        //document.getElementById(button.dataset.relevantinput).style.display = "none";
        document.getElementById(`${button.dataset.relevantinput}Input`).value = "";
        button.classList.remove("inverseAccent");
        document.getElementById(button.dataset.relevantinput).classList.toggle("collapsed");
      }
      else{
        //document.getElementById(button.dataset.relevantinput).style.display = "block";
        button.classList.add("inverseAccent");
        document.getElementById(button.dataset.relevantinput).classList.toggle("collapsed");
      }
    });
  });
}

async function InitChat() {
  await GetDetails();
  console.debug("GOT DETAILS");
  SetSidebar();
  console.debug("SET SIDEBAR");
  let savedUsersObject = (await GetSavedUsers())
  savedUsers = savedUsersObject.users;
  savedUsersMap = new Map(savedUsers);
  onlineUsers = savedUsersObject.onlineUsers;
  console.debug("GOT SAVED USERS and OnlineUsers");
  DisplaySetUsers("chatlistUL", "chat", "contactBannerText",0,"asc","false",true);
  console.debug("DISPLAYED SAVED USERS")
  UserSearchBar(document.getElementById("chatlistUL"), document.getElementById("searchForUserInput"));
  console.debug("SET SEARCH BAR");
  SetupMessenger();
  console.debug("SET MESSENGER");
  SetAddUserButton();
  console.debug("Set Add User Button");
  activeSessions = await GetSessions();
  console.debug("Got open sessions");
  SetMessageButtons();
  console.debug("Set Message Buttons");
  themes = await GetThemes();
  console.debug("GOT THEMES");
  UpdateCSSTheme(currentTheme);
  console.debug("SET CURRENT THEME");

  //Setting up draft saver
  const messageBox = document.getElementById("messagingInputField");
  const autoDraftSaveInterval = setInterval(async () => {
    if(targetedUserIdentifier != null) {
      await SaveDraft(targetedUserIdentifier, messageBox.value);
      console.debug("Draft saved!");
    }
  }, 10000);

}

async function InitSettings(){
  await GetDetails();
  console.debug("GOT DETAILS");
  SetSidebar();
  console.debug("SET SIDEBAR");
  themes = await GetThemes();
  console.debug("GOT THEMES");
  UpdateCSSTheme(currentTheme);
  console.debug("SET CURRENT THEME");
  SetupSettingButtons();
  console.debug("Set Setting Buttons")
}

async function InitKeyDisplay(){
  await GetDetails();
  console.debug("GOT DETAILS");
  SetSidebar();
  console.debug("SET SIDEBAR");
  themes = await GetThemes();
  console.debug(`GOT THEMES - CURRENT THEME : ${currentTheme}`);
  UpdateCSSTheme(currentTheme);
  console.debug("SET CURRENT THEME");
  DisplayKeyData();
  console.debug("SET KEY DATA");
  let savedUsersObject = (await GetSavedUsers())
  savedUsers = savedUsersObject.users;
  savedUsersMap = new Map(savedUsers);
  onlineUsers = savedUsersObject.onlineUsers;
  console.debug("GOT SAVED USERS");
  UserSearchBar(document.getElementById("otherUsersListUL"), document.getElementById("searchForUserInput"));
  console.debug("SET SEARCH BAR");
  
  let usersLiList = DisplaySetUsers("otherUsersListUL", "otherUserOverviewRecentMessages", "", 2, "desc", "false");
  usersLiList.forEach(userLi => {
    userLi.addEventListener('click', () => {
      DisplayOtherUserDetails(userLi.id);
    });
  });
}

const page = document.querySelector('meta[name="viewport"]').dataset.page;

const socket = io();

socket.on('newMessageIncoming', (msg) => {
  console.debug(`New message recieved at ${msg.timestamp} from ${msg.senderIdentifier} with type ${msg.type}`);
  console.debug(`page = ${page}, targetedUserIdentifier = ${targetedUserIdentifier}, ${targetedUserIdentifier == msg.senderIdentifier}`);
  if(page === "chat" && targetedUserIdentifier === msg.senderIdentifier){ 
    console.debug("Now refreshing messages");
    messages.push(msg);
    console.debug(`${typeof(messages)}`);
    console.debug("New Messages : ", messages)
    DisplayMessages(messages, targetedUserIdentifier, "chat", "contactBannerText")
  }

  //Notification
  console.debug(`SEND NOTIFICATIONS : ${sendNotifications}`);
  if(sendNotifications){
    console.debug("Sending Notification");
    let notificationBody = "";
    if(msg.type == "message"){
      notificationBody = msg.message.slice(0, notificationMaxLengthChars);
      if(notificationBody.length + 3 < msg.message.length) notificationBody += "...";
      else notificationBody = msg.message.slice(0, notificationMaxLengthChars + 3); 
    }
    else{
       const fullFilename = `File : ${msg.userFilename}.${msg.extension}`;
      if (fullFilename.length > notificationMaxLengthChars) {
        notificationBody = fullFilename.slice(0, notificationMaxLengthChars - 3) + "...";
      } else {
        notificationBody = fullFilename;
      }
    }
    const notif = new Notification(`New Message from ${msg.displayName}`, 
      { "body" : notificationBody,
        "icon" : `http://localhost:${backendPort}/api/static/icons/favicon.ico`
      });
    
    setTimeout(() => notif.close(), 3000);
  }

});

socket.on('onlineUsersUpdate', (msg) => {
  console.debug(`New online users : ${msg.onlineUsers} ${typeof(msg.onlineUsers)} ${typeof(onlineUsers)}`);
  onlineUsers = msg.onlineUsers;
  DisplaySetUsers("chatlistUL", "chat", "contactBannerText",0,"asc","false",true);
  if(targetedUserIdentifier !== null) DisplayMessages(messages, targetedUserIdentifier, "chat", "contactBannerText");
})

socket.on("newMessageDelete", async (msg) => {
  console.debug("Received newMessageDelete");
  messages = await GetMessages(targetedUserIdentifier, 0, "asc", "false");
  DisplayMessages(messages, targetedUserIdentifier, "chat", "contactBannerText");
});

socket.on("activeSessionsUpdate", (msg) => {
  onlineUsers[msg.identifier] = msg.status;
  console.log("activeSessionsUpdateStatus", msg.status, typeof(msg.status));
  if(msg.status === false) activeSessions.splice(activeSessions.indexOf(msg.identifier), 1);
  else activeSessions.push(msg.identifier);
  if(targetedUserIdentifier === msg.identifier){
    console.log("Setting button", activeSessions);
    SetSessionButton(msg.identifier);
  } 
});

socket.on("messageLockStatusChange", async (msg) => {
  console.debug("Received messageLockStatusChange");

  if(msg["identifier"] == targetedUserIdentifier){
    messages = await GetMessages(targetedUserIdentifier, 0, "asc", "false");
    DisplayMessages(messages, targetedUserIdentifier, "chat", "contactBannerText");
  }
});

socket.on("newUserUpdate", async (msg) => {
  console.debug("New user :", msg.identifier, msg.displayName);
  let savedUsersObject = (await GetSavedUsers())
  savedUsers = savedUsersObject.users;
  savedUsersMap = new Map(savedUsers);
  onlineUsers = savedUsersObject.onlineUsers;
  console.debug("GOT SAVED USERS and OnlineUsers");
  DisplaySetUsers("chatlistUL", "chat", "contactBannerText",0,"asc","false",true);
});

console.log(`PAGE : ${page}`);
if(page === "chat") InitChat();
else if(page === "settings") InitSettings();
else if(page === "keydisplay") InitKeyDisplay();