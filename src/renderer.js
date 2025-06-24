let identifier = null;
let savedUsers = null;
let savedUsersMap = null;
let messages = null;
let themes = null;
let currentTheme = null;
let publicKey = null;
let displayName = null;
let targetedUserIdentifier = null;

//Consts
const stylesheet = document.documentElement.style;

//Display Variables
let maxThemeButtonsInRow = 4;

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

  } catch (error) {
      console.error("Fetch error:", error);
  }
}

function SetSidebar() {
    //Chat page
    document.getElementById('chatIcon').addEventListener('click', () => {
        window.electronAPI.navigateTo('src/index.html');
    });

    //Settings page
    document.getElementById('settingsIcon').addEventListener('click', () => {
        window.electronAPI.navigateTo('src/settings.html');
    });

    //Key Display page
    document.getElementById('keyIcon').addEventListener('click', () => {
        window.electronAPI.navigateTo('src/keydisplay.html');
    });
}

async function GetSavedUsers() {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetSavedUsers`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    
    console.log("Saved Users fetched:", data);

    return data
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

function DisplaySetUsers(id, chatID, banner="", amount = 0, sort = "asc" ,reversed = "false") {
  let chatListUL = document.getElementById(id);
  chatListUL.innerHTML = "";

  let savedUsersLi = [];

  savedUsers.forEach(savedUser => {
    const li = document.createElement("li");
    li.className = "displayText chatlistElement underlineFade";
    li.id = savedUser[0];
    li.textContent = savedUser[1];
    li.addEventListener("click",() => {
      targetedUserIdentifier = li.id;
      GetDisplayMessages(li.id, chatID, banner, amount, sort, reversed);
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
        div.textContent = messageToDisplay[2];
        chat.appendChild(div);
    });

    if(banner !== "") {
      let messageLabel = document.getElementById(banner);
      messageLabel.textContent = savedUsersMap.get(messagerIdentifier);
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

async function SetTheme(newTheme) {
 try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/Post/SetTheme`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({"newTheme" : newTheme})
    });

    const data = await response.json();
    console.log("POST Response in SetTheme:", data);
    
  } catch (error) {
    console.error("Error posting data:", error);
  }

  UpdateCSSTheme(newTheme);
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
        SetTheme(themeButton.id);
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
  messageBox.value = "";
}

function SetupMessenger() {
  const messageBox = document.getElementById("messagingInputField");
  const messageSendButton = document.getElementById("sendMessageButton");

  messageSendButton.addEventListener("click", () => {
    SendMessage(messageBox, targetedUserIdentifier);
  });
}

async function InitChat() {
  await GetDetails();
  console.debug("GOT DETAILS");
  SetSidebar();
  console.debug("SET SIDEBAR");
  savedUsers = await GetSavedUsers();
  savedUsersMap = new Map(savedUsers);
  console.debug("GOT SAVED USERS");
  DisplaySetUsers("chatlistUL", "chat", "contactBannerText");
  console.debug("DISPLAYED SAVED USERS")
  UserSearchBar(document.getElementById("chatlistUL"), document.getElementById("searchForUserInput"));
  console.debug("SET SEARCH BAR");
   SetupMessenger();
  console.debug("SET MESSENGER");
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
  SetThemeButtons();
  console.log("SET THEME BUTTONS");
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
  savedUsers = await GetSavedUsers();
  savedUsersMap = new Map(savedUsers);
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
console.log(`PAGE : ${page}`);
if(page === "chat") InitChat();
else if(page === "settings") InitSettings();
else if(page === "keydisplay") InitKeyDisplay();