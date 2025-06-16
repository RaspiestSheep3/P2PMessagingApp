let identifier = null;
let savedUsers = null;
let savedUsersMap = null;
let messages = null;
let themes = null;

//Display Variables
let maxThemeButtonsInRow = 4;
backendPort = 5000;

async function GetDetails() {
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

function SetSidebar() {
    //Chat page
    document.getElementById('chatIcon').addEventListener('click', () => {
        window.electronAPI.navigateTo('src/index.html');
    });

    //Settings page
    document.getElementById('settingsIcon').addEventListener('click', () => {
        window.electronAPI.navigateTo('src/settings.html');
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

async function GetMessages(otherIdentifier) {
  try {
    const response = await fetch(`http://127.0.0.1:${backendPort}/api/GetMessages/${otherIdentifier}`);
    if (!response.ok) throw new Error("Network response was not OK");
    const data = await response.json();
    console.log("Messages fetched:", data);

    return data;
  } catch (error) {
      console.error("Fetch error:", error);
  }
}

function DisplaySetUsers() {
  let chatListUL = document.getElementById("chatlistUL");
  chatListUL.innerHTML = "";
  savedUsers.forEach(savedUser => {
    const li = document.createElement("li");
    li.className = "displayText chatlistElement underlineFade";
    li.id = savedUser[0];
    li.textContent = savedUser[1];
    chatListUL.appendChild(li);
  });
}

function DisplayMessages(messagesToDisplay, messagerIdentifier) {
    let chat = document.getElementById("chat");
    chat.innerHTML = "";
    messagesToDisplay.forEach(messageToDisplay => {
        const div = document.createElement("div");
        div.className = "displayText message";

        if(messageToDisplay[1] === identifier) div.classList.add("messageOutgoing");
        else div.classList.add("messsageIncoming");
        div.textContent = messageToDisplay[2];
        chat.appendChild(div);
    });

    let messageLabel = document.getElementById("contactBannerText");
    messageLabel.textContent = savedUsersMap.get(messagerIdentifier);
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
      themeRow.appendChild(themeButton);
      console.debug(themeButtonData);
    });
    
    themeButtonsArea.appendChild(themeRow);
  }
}

async function InitChat() {
    await GetDetails();
    console.debug("GOT DETAILS");
    SetSidebar();
    console.debug("SET SIDEBAR");
    savedUsers = await GetSavedUsers();
    savedUsersMap = new Map(savedUsers);
    console.debug("GOT SAVED USERS");
    DisplaySetUsers();
    console.debug("DISPLAYED SAVED USERS")
    messages = await GetMessages("B");
    console.debug("GOT MESSAGES");
    DisplayMessages(messages, "B");
    console.debug("DISPLAYING MESSAGES")
}

async function InitSettings(){
    await GetDetails();
    console.debug("GOT DETAILS");
    SetSidebar();
    console.debug("SET SIDEBAR");
    themes = await GetThemes();
    console.debug("GOT THEMES");
    SetThemeButtons();
}

const page = document.querySelector('meta[name="viewport"]').dataset.page;
console.log(`PAGE : ${page}`);
if(page === "chat") InitChat();
else if(page === "settings") InitSettings();