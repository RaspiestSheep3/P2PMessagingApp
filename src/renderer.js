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

//Consts 
const stylesheet = document.documentElement.style;
const now = new Date();
const maxThemeButtonsInRow = 4; 
const notificationMaxLengthChars = 37;
const onlineDisplayDict = {
  true : "🟢",
  false : "🔴"
};

//!TEMP - FOR TESTING MULTIPLE USERS
const backendPort = window.myAPI.backendPort;
console.log(`RUNNING ON BACKEND PORT ${backendPort}`);

async function GetDetails() {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetDetails`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Details fetched:", data);
    identifier = data["identifier"]   
    currentTheme = data["theme"] 
    publicKey = data["publicKey"]
    displayName = data["displayName"]
    maxMessageLength = data["maxMessageLength"]
    sendNotifications = data["sendNotifications"].toLowerCase() === "true"
    use12hFormat = data["use12hFormat"].toLowerCase() === "true"

  } catch (error) {
      console.error("Fetch error:", error);
  }
}

function SetSidebar() {
    //Chat page
    document.getElementById('chatIcon').addEventListener('click', () => {
        window.electronAPI.navigateTo('index.html');
    });

    //Settings page
    document.getElementById('settingsIcon').addEventListener('click', () => {
        window.electronAPI.navigateTo('settings.html');
    });

    //Key Display page
    document.getElementById('keyIcon').addEventListener('click', () => {
        window.electronAPI.navigateTo('keydisplay.html');
    });
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
    li.addEventListener("click",() => {
      targetedUserIdentifier = li.id;
      GetDisplayMessages(li.id, chatID, banner, amount, sort, reversed);
      if(sessionButton) SetSessionButton(li.id);
    });
    chatListUL.appendChild(li);
    savedUsersLi.push(li);
  });

  return savedUsersLi;
}

function DisplayMessages(messagesToDisplay, messagerIdentifier, chatID, banner="") {
    let chat = document.getElementById(chatID);
    chat.innerHTML = "";
    messagesToDisplay.forEach(messageToDisplay => {
        const div = document.createElement("div");
        div.className = "displayText message";

        if(messageToDisplay[1] === identifier) div.classList.add("messageOutgoing");
        else div.classList.add("messsageIncoming");
        
        let messageTimestampArray = (messageToDisplay[0].split(" ")[1]).split(":");
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
        
        div.innerHTML = messageToDisplay[2].replaceAll("\n", "<br>");
        div.innerHTML = div.innerHTML + `<div class="timestamp">${messageTimestamp}</div>`;
        chat.appendChild(div);
    });

    if(banner !== "") {
      let messageLabel = document.getElementById(banner);
      console.log(`Messanger Identifier in DisplayMessages : ${messagerIdentifier} ${onlineUsers}`);
      messageLabel.textContent = `${savedUsersMap.get(messagerIdentifier)} ${onlineDisplayDict[onlineUsers.includes(messagerIdentifier)]}`;
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

async function SendMessage(messageBox, otherUserIdentifier) {
  const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/SendMessageToUser/${otherUserIdentifier}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({"message" : messageBox.value})
    });
  console.log(response);

  const pad = (n) => n.toString().padStart(2, '0');
  const timestamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;
  messages.push([timestamp, identifier, messageBox.value]);
  DisplayMessages(messages, targetedUserIdentifier, "chat", "contactBannerText");

  messageBox.value = "";
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
     charCount.textContent = `0/${maxMessageLength}`;
    SendMessage(messageBox, targetedUserIdentifier);
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
}

async function ChangeSession(otherUserIdentifier, type){
  const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/ChangeSession`, {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({"identifier" : otherUserIdentifier, "type" : type})
  });
  console.log(response);
}

function SetSessionButton(otherUserIdentifier) {
  const buttonElement = document.getElementById("StartSessionButton");
  if(activeSessions.includes(otherUserIdentifier)) buttonElement.textContent = "End Session";
  else buttonElement.textContent = "Start Session";
  buttonElement.addEventListener("click", () => {
    if(activeSessions.includes(otherUserIdentifier)){
      console.debug("Closing session");
      activeSessions.splice(activeSessions.indexOf(otherUserIdentifier), 1);
      buttonElement.textContent = "Start Session";
      ChangeSession(otherUserIdentifier, "end");
    }
    else {
      console.debug("Starting session");
      activeSessions.push(otherUserIdentifier);
      buttonElement.textContent = "End Session";
      ChangeSession(otherUserIdentifier, "start");
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
  themes = await GetThemes();
  console.debug("GOT THEMES");
  UpdateCSSTheme(currentTheme);
  console.debug("SET CURRENT THEME");
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
  console.debug(`New message recieved at ${msg.timestamp} from ${msg.senderIdentifier} : ${msg.message}`);
  console.debug(`page = ${page}, targetedUserIdentifier = ${targetedUserIdentifier}, ${targetedUserIdentifier == msg.senderIdentifier}`);
  if(page === "chat" && targetedUserIdentifier === msg.senderIdentifier){
    console.debug("Now refreshing messages");
    messages.push([msg.timestamp, msg.senderIdentifier, msg.message]);
    console.debug(`${typeof(messages)}`);
    DisplayMessages(messages, targetedUserIdentifier, "chat", "contactBannerText")
  }

  //Notification
  console.debug(`SEND NOTIFICATIONS : ${sendNotifications}`);
  if(sendNotifications){
    let notificationBody = msg.message.slice(0, notificationMaxLengthChars);
    if(notificationBody.length + 3 < msg.message.length) notificationBody += "...";
    else notificationBody = msg.message.slice(0, notificationMaxLengthChars + 3);
    new Notification(`New Message from ${msg.senderIdentifier}`, 
      { "body" : notificationBody,
        "icon" : `http://localhost:${backendPort}/api/static/icons/favicon.ico`
      });
  }

});

console.log(`PAGE : ${page}`);
if(page === "chat") InitChat();
else if(page === "settings") InitSettings();
else if(page === "keydisplay") InitKeyDisplay();