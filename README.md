# CyberRune - A P2P Messaging App

## Overview
CyberRune is an open-source **Peer-To-Peer Messaging App** that **avoids the usage of central servers** to create a more robust and honest messaging system. It is designed for usage in countries without freedom of internet, to try avoid the lack of messaging servers and ensure free speech. 

---

## Features

- **True Peer-to-Peer Messaging**  
  No central relays mean peers can talk to each other in perfect privacy using a robust and decentralised system

- **End-to-End Encryption**  
  Messages and file transfers are encrypted using AES and ED25519 signatures to ensure maximum security and privacy

- **Secure File Transfers**  
  Files are encrypted before being sent and securely decrypted upon receipt

- **Timeable Messages**
    Messages can be set to automatically lock or unlock after a certain amount of time

- **Easily Adjustable Settings** 
    Many different options exist on how to adjust key aspects such as theme and date format for maximum customisability

- **Logging & Debug Mode**  
  Backend and frontend logs include warnings, errors, and event traces for easier debugging

- **Electron Frontend Integration**  
  Clean and responsive interface with real-time updates powered by the backend Flask API

- **QoL Features** 
    A variety of QoL features are available, such as the ability to natively view images without download, draft saving and the ability to download sent files in just one click

---

## Architecture Overview

- **Python** is used to form the backend of the project
    - The **socket** module is used to handle connections using the **TCP** protocol
    - **AES** is used through the **cryptography** module, with **DHE** being used to securely generate and share the key
    - Messages are authenticated using **ED25519**, and we use **HMAC** to ensure messages have not been tampered with 
    - **SQL** is used to track users and messages using **sqlite3**, and we encrypt these using **Fernet** keys stored using **keyring**
    - Logging is done through the **logging** module, which allows for different warning levels to avoid clutter 
    - **Flask API** is used to provide a gateway for the frontend to render the project
- **Electron** is used to render the frontend, relying on the **Chromium** engine to render the **HTML, CSS and Javascript** that provides a clear user display

---

## Learning Results

- I improved my **network** skills, and learnt different techniques such as **DHE** to ensure secure P2P communication

- I learnt about **hashing** and its importance in ensuring data has not been malformed or tampered with

- I improved my **cybersecurity** skills and knowledge by learning about **Elliptical Curve Cryptography** and its benefits over standard methods such as RSA

- I learnt how to use **SQL** and its power for database management

- I significantly improved my **frontend skills**, notably my **JavaScript** abilities due to the high complexity of this project

- I improved my **problem solving skills** by having to consider how to overcome the restrictions provided by a lack of central servers

- This is my biggest project to date, so I had to learn how to deal with **management of big projects**, such as being forced to adhere to good practices and improve my time management

--- 

## Future Improvements

- **TURN** implemenation to deal with NAT Traversal

- **Group Chats** to help my project compete with traditional systems such as WhatsApp and Signal

- **Offline Message Storing** for when peers are offline to help with the UX

---

## Images Showcase

**Messages Display** 

![Messages Screenshot](Display%20Images/Cyberpunk%20Blank.png)

---

![Messages Screenshot](Display%20Images/Cyberpunk%20Messages.png)

---

![Messages Screenshot](Display%20Images/Gold%20All%20Messages.png)

---

**Settings Display** 

![Messages Screenshot](Display%20Images/Cyberpunk%20Settings.png)

---

**Key Display**

![Messages Screenshot](Display%20Images/Cyberpunk%20Key%20Display.png)

---

![Messages Screenshot](Display%20Images/Gold%20Key%20Display%20Filled.png)