import socket
import threading
import logging
import colorlog
import random
import json
import math
import hmac
import hashlib
import os
import base64
import sqlite3
import re
import keyring
import queue
import io
import mimetypes
from PIL import Image
from time import sleep
from datetime import datetime
from dataclasses import dataclass
from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_socketio import SocketIO
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

#!TEMP - MAKE BETTER SYSTEM FOR IDENTIFICATION
identifier = input("PEER IDENTIFIER : ")

#!TEMP - MAKE BETTER SYSTEM FOR DISPLAY NAMES
displayName = input("DISPLAY NAME : ")

#!TEMP - MAKE BETTER WAY TO SET LISTEN PORT
incomingConnectionPortGlobal = int(input("INCOMING CONNECTION PORT : "))

@dataclass
class PeerDetail:
    identifier: str
    publicKey: str
    displayName : str
    host: str
    port: int

@dataclass
class FileUpload:
    ownerIdentifier : str
    targetIdentifier : str
    fileExtension : str
    fileSizeBytes : int
    timestamp : str
    isUploader : bool
    totalChunks : int
    userFilename : str

class Peer():
    def __init__ (self, incomingConnectionHost="0.0.0.0", incomingConnectionPort = incomingConnectionPortGlobal, socketioInstance = None):
        self.connections = []
        self.incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.incomingConnectionHost = incomingConnectionHost
        self.incomingConnectionPort = incomingConnectionPort
        self.connectedAddrs = []
        self.activeConnectionThreads = []
        self.DHEBitLength = 512 #TODO : Consider 1024 in the future
        self.messagePadLength = 8192
        self.messageLength = 1900 #A bit less than 4x bcs with UTF8 we can use 4B/char, and we need some size for overhead stuff
        self.knownUsers = []
        self.databaseName = f"Peer{identifier}Database.db"
        self.publicKey = None
        self.privateKey = None
        self.fernetKey = None
        self.hashedIdentifier =  hashlib.sha256(identifier.encode()).hexdigest()
        self.appName = "P2PMessagingApp"
        self.openConnections = {}
        self.openConnectionsLock = threading.Lock()
        self.messagingQueues = {}
        self.connectionLocks = {}
        self.socketio = socketioInstance
        self.onlineUsersDict = {} #Used to check which users are online
        self.onlineUsersEventDict = {}
        self.activeAESKeys = {}
        self.activeSBytes = {}
        self.onlineUsersDictLock = threading.Lock()
        self.filesBeingUploaded = []
        self.fileChunkHeaderSizeBytes = 1024
        self.fileChunkSizeBytes = 64 * 1024 #64 KiB
        
        #Logging setup
        self.logFormatter = colorlog.ColoredFormatter(
            "%(log_color)s%(levelname)s: %(message)s",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        )

        # Create a console handler
        self.consoleLogHandler = logging.StreamHandler()
        self.consoleLogHandler.setFormatter(self.logFormatter)
        
        # General handler
        with open(f"Peer{identifier}General.log", "w") as f:
            f.write("") #Clearing file
        self.generalLogHandler = logging.FileHandler(f"Peer{identifier}General.log")
        self.generalLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.generalLogHandler.setLevel(logging.DEBUG) 

        #Error handler
        with open(f"Peer{identifier}Errors.log", "w") as f:
            f.write("")
        self.errorLogHandler = logging.FileHandler(f"Peer{identifier}Errors.log")
        self.errorLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.errorLogHandler.setLevel(logging.ERROR)  
        
        # Create a logger
        self.logger = logging.getLogger("colorLogger")
        self.logger.setLevel(logging.DEBUG)

        # Add handlers to the logger
        self.logger.addHandler(self.consoleLogHandler)  # Logs to console
        self.logger.addHandler(self.generalLogHandler)    
        self.logger.addHandler(self.errorLogHandler)          
    
    def Start(self):
        try:
            self.incomingConnectionSocket.bind((self.incomingConnectionHost, self.incomingConnectionPort))
            self.incomingConnectionSocket.listen(5)
            self.logger.info("PEER STARTED UP")
            
            #SQL
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS savedUsers (
                    identifier STRING NOT NULL UNIQUE,
                    publicKey BLOB NOT NULL,
                    displayName TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL
                )
            ''')

            cursor.execute("SELECT * FROM savedUsers")
            rows = cursor.fetchall()
            self.knownUsers = {row[0] : PeerDetail(row[0], row[1], row[2], row[3], row[4]) for row in rows}

            # Commit changes and close the connection
            conn.commit()
            conn.close()
            
            #Setup ED25519 - Shorter keys than RSA due to elliptical witchery
            if(os.path.isfile(f"public{identifier}.key") and (os.path.isfile(f"private{identifier}.key"))):
                with open(f"private{identifier}.key", "rb") as f:
                    privateKey = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
                with open(f"public{identifier}.key", "rb") as f:
                    publicKey = ed25519.Ed25519PublicKey.from_public_bytes(f.read())
            
            else:
                #Making new ED25519 Keys
                privateKey = ed25519.Ed25519PrivateKey.generate()
                publicKey = privateKey.public_key()
                
                with open(f"private{identifier}.key", "wb") as f:
                    f.write(privateKey.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                
                with open(f"public{identifier}.key", "wb") as f:
                    f.write(publicKey.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    ))
            
            self.publicKey = publicKey
            self.privateKey = privateKey
            
            #Setting up Fernet key - used for SQL encryption
            keyringKey = keyring.get_password(self.appName, self.hashedIdentifier)
            if(keyringKey == None):
                #Need to make a new keyring key
                self.fernetKey = Fernet.generate_key()
                keyring.set_password(self.appName, self.hashedIdentifier, self.fernetKey.decode())
            else:
                self.fernetKey = keyringKey.encode()
            
            #self.logger.warning(f"FERNET KEY (DELETE THIS) : {self.fernetKey}")
            #self.logger.warning(f"KNOWN USERS (DELETE THIS) : {self.knownUsers}")
            
            #Finding out who is online
            with self.onlineUsersDictLock:
                self.onlineUsersDict = {} 
            for knownUser in self.knownUsers:
                user = self.knownUsers[knownUser]
                self.onlineUsersEventDict[user.identifier] = threading.Event()
                self.logger.debug(f"Now connecting to {user}")
                outputSocket = self.StartSession(otherIdentifier=user.identifier, isOnlineCheck=True, event=self.onlineUsersEventDict[user.identifier])
                if(outputSocket == None):
                    self.logger.info(f"Error starting session with {user} in Start - user is offline")
                    continue
                else:
                    self.logger.info(f"User {user} is online - sending message")
                    outputSocket.send(json.dumps({"type" : "isOnline", "identifier" : identifier}).encode().ljust(self.messagePadLength, b"\0"))
                    self.onlineUsersEventDict[user.identifier].wait()
                    self.logger.info(f"Now received response from {user.identifier}")
                    self.EndSession(user.identifier)

            with self.onlineUsersDictLock:
                self.logger.debug(f"Online users dict in Start : {self.onlineUsersDict}")
            
        except Exception as e:
            self.logger.error(f"Error {e} in Start", exc_info=True)
        
    #Public Key Visualiser
    def VisualisePublicKey(self, userIdentifier):
        try:
            key = None
            if(userIdentifier == identifier):
                key = self.publicKey.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    ).hex()
            elif(userIdentifier in self.knownUsers):
                key = (self.knownUsers[userIdentifier].publicKey).hex()
            
            if(key != None):
                key = ":".join(key[i:i+4] for i in range(0, len(key), 4)) #Writes as abcd:1234:efgh
            
            return key
        except Exception as e:
            self.logger.error(f"Error {e} in VisualisePublicKey", exc_info=True)
        
    def WaitForIncomingRequests(self):
        try:
            while True:
                self.logger.info("WAITING FOR REQUESTS")
                peerSocket, addr = self.incomingConnectionSocket.accept()
                self.logger.info(f"MESSAGE FROM {addr}")
                if(addr not in self.connectedAddrs):
                    self.logger.info(f"{addr} IS A NEW ADDRESS")
                    self.connectedAddrs.append(addr)
                    thread = threading.Thread(target=self.HandleIncomingConnection, args=(peerSocket,), daemon=True)
                    self.activeConnectionThreads.append(thread)
                    thread.start()
        except Exception as e:
            self.logger.error(f"Error {e} in WaitForIncomingRequests", exc_info=True)
        
    def ListenForMessages(self, peerSocket, senderIdentifier, sBytes, AESKey, senderPublicKey, event=None):
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            while (senderIdentifier in self.openConnections) and (peerSocket.fileno() != -1):
                #with self.connectionLocks[senderIdentifier]:
                self.logger.debug(f"Sender Identifier in ListenForMessages is {senderIdentifier}")
                
                if peerSocket.fileno() == -1: #Checks if the connections open
                    self.logger.warning(f"{senderIdentifier} socket is closed in ListenForMessages")
                    return
                with self.connectionLocks[senderIdentifier]:
                    self.logger.debug("Holding lock in ListenForMessages")
                    if(senderIdentifier not in self.openConnections):
                        self.logger.debug("Returning from ListenForMessages due to not in openConnections")
                        return
                
                self.logger.debug("No longer holding lock in ListenForMessages")
                
                messageRaw = b""
                if peerSocket.fileno() != -1:
                    try:
                        messageRaw = peerSocket.recv(self.messagePadLength)
                    except Exception as e:
                        self.logger.error(f"Socket error in ListenForMessages: {e}", exc_info=True)
                else:
                    self.logger.error(f"PeerSocket.fileno = -1 in ListenForMessages")
                
                if(messageRaw == b""):
                    self.logger.debug("Returning from ListenForMessages due to b''")
                    return
                else:
                    #self.logger.debug(f"messageRaw in ListenForMessages : {messageRaw}")
                    message = json.loads(messageRaw.rstrip(b"\0").decode())
                    self.logger.debug(f"Message in ListenForMessages : {message}")
                    if(message["type"] == "closeSocket"):
                        self.logger.warning(f"Shutting connection with {senderIdentifier}")
                        peerSocket.send(json.dumps({"type" : "closeSocketResponse"}).encode().ljust(self.messagePadLength, b"\0"))
                        sleep(1)
                        peerSocket.shutdown(socket.SHUT_RDWR)
                        peerSocket.close()
                        del self.openConnections[senderIdentifier]
                        del self.activeAESKeys[senderIdentifier]
                        del self.activeSBytes[senderIdentifier]
                        
                        self.logger.warning(f"New OpenConnections in ListenForMessages : {self.openConnections}")
                        return
                    
                    elif(message["type"] == "closeSocketResponse"):
                        self.logger.warning(f"Shutting connection with {senderIdentifier} - Received confirmation")
                        peerSocket.shutdown(socket.SHUT_RDWR)
                        peerSocket.close()
                        del self.openConnections[senderIdentifier]
                        del self.activeAESKeys[senderIdentifier]
                        del self.activeSBytes[senderIdentifier]
                        
                        self.logger.warning(f"New OpenConnections in ListenForMessages : {self.openConnections}")
                        return                        
                    elif(message["type"] == "isOnline"):
                        self.logger.info(f"Received isOnline check from {message['identifier']}")
                        with self.onlineUsersDictLock:
                            self.onlineUsersDict[message["identifier"]] = True
                        self.logger.debug(f"New Online Users Dict : {self.onlineUsersDict}")
                        peerSocket.send(json.dumps({"type" : "isOnlineResponse" , "valid" : "true" , "identifier" : identifier}).encode().ljust(self.messagePadLength, b"\0"))
                    
                    elif(message["type"] == "isOnlineResponse"):
                        self.logger.debug(f"Recieved isOnlineResponse from {message['identifier']}")
                        with self.onlineUsersDictLock:
                            self.onlineUsersDict[message["identifier"]] = True
                        #self.logger.debug(f"New Online Users Dict : {self.onlineUsersDict}")
                        event.set()
                    
                    elif(message["type"] == "fileUploadNew"):
                        self.logger.debug(f"File Upload Request from {message['identifier']}")
                        binaryLength = message["length"]
                        totalChunks = math.ceil(message["length"] / self.fileChunkSizeBytes)
                        messageTimestamp = message["timestamp"]
                        extension = message["fileExtension"]
                        userFilename = message["userFilename"]
                        aesGCM = AESGCM(AESKey)
                        
                        fileUploadClass = FileUpload(message["identifier"], identifier, extension, binaryLength ,messageTimestamp ,False, totalChunks,userFilename)
                        self.filesBeingUploaded.append(fileUploadClass)
                        self.logger.debug(f"Current file upload list in ListenForMessages: {self.filesBeingUploaded}")
                    
                        dataList = [None] * totalChunks

                        receivingData = True
                        while receivingData:
                            chunkMessage = json.loads(peerSocket.recv(self.fileChunkHeaderSizeBytes).rstrip(b"\0").decode())
                            if(chunkMessage["type"] == "fileUploadEnd"):
                                receivingData = False
                            elif(chunkMessage["type"] == "fileUploadChunk"):
                                binaryCiphertext = peerSocket.recv(chunkMessage["chunkLength"])
                                nonce = base64.b64decode(chunkMessage["nonce"])
                                
                                hmacTag = base64.b64decode(chunkMessage["hmacTag"])
                                signature = base64.b64decode(chunkMessage["signature"])
                                #HMAC test   
                                
                                expectedHmacTag = hmac.new(self.activeSBytes[senderIdentifier], binaryCiphertext, hashlib.sha256).digest()
                                if hmac.compare_digest(hmacTag, expectedHmacTag):
                                    self.logger.info("HMAC TAG CORRECT")
                                else:
                                    self.logger.error("HMAC TAG INCORRECT - DATA TAMPERED OR FORGED for file")
                                    return
                                
                                binaryPlaintext = aesGCM.decrypt(nonce, binaryCiphertext, None)
                                
                                #Signature test
                                try:
                                    self.logger.warning(f"SIGNATURE (DELETE THIS) : {senderPublicKey} {type(senderPublicKey)}")
                                    senderPublicKey.verify(signature, binaryPlaintext)
                                except InvalidSignature:
                                    self.logger.critical(f"INVALID SIGNATURE - DO NOT TRUST")
                                    return
                                
                                dataList[chunkMessage["chunkIndex"]] = binaryPlaintext 
                                self.logger.debug(f"Recieved chunk {chunkMessage['chunkIndex']} (len : {len(dataList[chunkMessage['chunkIndex']])})")
                        
                        self.logger.debug(f"Recieved all chunks : {len(dataList)}, expected {totalChunks}")
                        self.filesBeingUploaded.remove(fileUploadClass)
                        
                        binaryData = b"".join(dataList)
                        
                        self.logger.debug(f"Binary data length in ListenForMessages : {len(binaryData)}")
                        
                        #Encrypting with Fernet
                        cipher = Fernet(self.fernetKey)
                        ciphertextFernet= cipher.encrypt(binaryData)    
                        
                        os.makedirs(f"uploads{identifier}", exist_ok=True)
                        with open(f"uploads{identifier}/{senderIdentifier}--{identifier}--{messageTimestamp}.bin", "wb") as fileHandle:
                            fileHandle.write(ciphertextFernet)
                            
                        cursor.execute(f"INSERT INTO chat{senderIdentifier} (timestamp, senderIdentifier, type, extension, filePath, userFilename) VALUES (?, ?, ?, ?, ?, ?)", (messageTimestamp, senderIdentifier, "file", extension, f"uploads{identifier}/{senderIdentifier}--{identifier}--{messageTimestamp}.bin", userFilename))
                        conn.commit()
                    elif(message["type"] == "message"):
                        self.logger.debug(f"message in ListenForMessages : {message}")
                        nonce = base64.b64decode(message["nonce"])
                        hmacTag = base64.b64decode(message["hmacTag"])
                        signature = base64.b64decode(message["signature"])
                        ciphertext = base64.b64decode(message["ciphertext"])
                        timestamp = message["timestamp"]
                        
                        self.logger.debug(f"Nonce on receipient : {nonce.hex()}")
                        self.logger.debug(f"Ciphertext in ListenerForMessages : {ciphertext.hex()}")
                        #HMAC test   
                        self.logger.debug(f"sBytes on ListenForMessages : {sBytes.hex()}") 
                        self.logger.debug(f"HMAC on receiver : {hmacTag.hex()}")
                        self.logger.debug(f"HMAC sBytes CHECK {self.activeSBytes[senderIdentifier] == sBytes} {sBytes.hex()} {hmacTag}")
                        self.logger.debug(f"AES KEY on receipient : {AESKey.hex()}")
                        expectedHmacTag = hmac.new(self.activeSBytes[senderIdentifier],nonce + ciphertext, hashlib.sha256).digest()
                        self.logger.debug(f"Expected HMAC on receiver : {expectedHmacTag.hex()}")
                        if hmac.compare_digest(hmacTag, expectedHmacTag):
                            self.logger.info("HMAC TAG CORRECT")
                        else:
                            self.logger.error("HMAC TAG INCORRECT - DATA TAMPERED OR FORGED for message")
                            return
                            
                        #Decrypting ciphertext
                        aesGCM = AESGCM(AESKey)
                        plaintextEncoded = aesGCM.decrypt(nonce, ciphertext, None)
                        plaintext = plaintextEncoded.decode()
                        
                        #Signature test
                        try:
                            self.logger.warning(f"SIGNATURE (DELETE THIS) : {senderPublicKey} {type(senderPublicKey)}")
                            senderPublicKey.verify(signature, plaintextEncoded)
                        except InvalidSignature:
                            self.logger.critical(f"INVALID SIGNATURE - DO NOT TRUST")
                            return
                        
                        self.logger.info(f"RECIEVED PLAINTEXT {plaintext} which was sent at {timestamp}")
                        
                        #Encrypting the message with Fernet
                        cipher = Fernet(self.fernetKey)
                        messageFernet = cipher.encrypt(plaintext.encode())
                        
                        #Adding message to the SQL
                        cursor.execute(f"INSERT INTO chat{senderIdentifier} (timestamp, senderIdentifier, message, type) VALUES (?, ?, ?, ?)", (timestamp, senderIdentifier, messageFernet, "message"))
                        conn.commit()
                        
                        #Alerting frontend about the new message
                        socketio.emit("newMessageIncoming", {
                            "timestamp" : timestamp,
                            "senderIdentifier" : senderIdentifier,
                            "message" : plaintext
                        })
             
            self.logger.debug(f"WHILE LOOP FINISHED : {(senderIdentifier in self.openConnections)}, {(peerSocket.fileno() != -1)}")       
        except Exception as e:
            self.logger.error(f"Error {e} in ListenForMessages", exc_info=True)
        finally:
            conn.close()
    
    def HandleIncomingConnection(self, peerSocket):
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            
            details = json.loads(peerSocket.recv(128).rstrip(b"\0").decode())
            self.logger.info(f"RECIEVED {details}")
            
            if(details["type"] == "sessionRequest"):
                incomingPayloadLength = details["DHEPayloadLength"]
                senderIdentifier = details["identifier"]
                if(senderIdentifier not in self.knownUsers):
                    shouldRequestKey = True
                else:
                    shouldRequestKey = False
                self.logger.info(f"NEW REQUEST FROM {senderIdentifier}")
                peerSocket.send(json.dumps({"type" : "sessionRequestAccept", "keyRequest" : shouldRequestKey, "identifier" : identifier}).encode().ljust(128, b"\0"))
                
                if(shouldRequestKey):
                    self.logger.debug("REQUESTING KEY")
                    senderDetails = json.loads(peerSocket.recv(128).rstrip(b"\0").decode())
                    senderPublicKey = senderDetails["publicKey"]
                    senderPublicKey = base64.b64decode(senderPublicKey)
                    
                    senderHost = senderDetails["host"]
                    senderPort = senderDetails["port"]
                    
                    #Updating SQL
                    cursor.execute("INSERT INTO savedUsers (identifier, publicKey, displayName, host, port) VALUES (?, ?, ?, ?, ?)", (senderIdentifier, senderPublicKey, details["displayName"], senderHost, senderPort))
                    
                    conn.commit()
                    self.knownUsers[senderIdentifier] = PeerDetail(senderIdentifier, senderPublicKey, details["displayName"], senderHost, senderPort) #Adding to dict
                else:
                    self.logger.debug(f"ALREADY HAVE KEY FOR {senderIdentifier}")
                    cursor.execute("SELECT * FROM savedUsers WHERE identifier = ?", (senderIdentifier,))
                    senderPublicKey = cursor.fetchone()[1]
                
                senderPublicKey = ed25519.Ed25519PublicKey.from_public_bytes(senderPublicKey)
                
                senderKeyRequest = json.loads(peerSocket.recv(64).rstrip(b"\0").decode())["type"]
                self.logger.debug(f"senderKeyRequest : {senderKeyRequest}")
                if(senderKeyRequest == "recipientPublicKeyRequest"):
                    #Sending public key
                    selfPublicKey = self.publicKey.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    
                    peerSocket.send(json.dumps({"type" : "recipientPublicKeyResponse", "recipientPublicKey" : base64.b64encode(selfPublicKey).decode(), "displayName" : displayName, "host" : peerSocket.getsockname()[0], "port" : self.incomingConnectionPort}).encode().ljust(256, b"\0"))
                
                payload = json.loads(peerSocket.recv(incomingPayloadLength).rstrip(b"\0").decode())
                self.logger.debug(f"PAYLOAD {payload}")
                
                #Making b, finding B
                b = self.GeneratePrime(self.DHEBitLength)
                B = pow(payload["g"], b, payload["p"])
                
                #finding s
                s = pow(payload["A"], b, payload["p"])
                
                #Sending B so sender can find s
                self.logger.debug(len(json.dumps({"B" : B})))
                peerSocket.send(json.dumps({"B" : B}).encode().ljust(int(self.DHEBitLength / 2), b"\0")) 
                
                sBytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")
                
                self.logger.info(f"FOUND sBYTES in HandleIncomingConnection : {len(sBytes)} {sBytes.hex()}")
                self.activeSBytes[senderIdentifier] = sBytes
                self.logger.debug(f"ActiveSBytes : {self.activeSBytes[senderIdentifier].hex()}")
                
                #Generating AES Key
                AESKey = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                    backend=default_backend()
                ).derive(self.activeSBytes[senderIdentifier])
                self.activeAESKeys[senderIdentifier] = AESKey
                
                #Avoiding SQL Injection - Only allow nums, letters and _s
                if(re.sub(r"\W+", "", senderIdentifier) != senderIdentifier):
                    self.logger.error(f'SENDER IDENTIFIER IS INVALID IN HANDLEINCOMINGCONNECTION - ATTEMPTED SQL INJECTION (ORG : {senderIdentifier})')
                    return
                
                #Creating the SQL table
                cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS chat{senderIdentifier} (
                    timestamp TEXT NOT NULL,
                    senderIdentifier TEXT NOT NULL,
                    message BLOB,
                    type TEXT NOT NULL,
                    extension TEXT,
                    filePath TEXT UNIQUE,
                    userFilename TEXT
                )
                ''')
                conn.commit()
                
                with self.openConnectionsLock:
                    self.openConnections[senderIdentifier] = peerSocket
            
                self.logger.warning(f"(DELETE THIS) OPEN CONNECTIONS : {self.openConnections}")
                
                #Making a lock for this message
                if(senderIdentifier not in self.connectionLocks):
                    self.connectionLocks[senderIdentifier] = threading.Lock()
                
                #Making queue
                if(senderIdentifier not in self.messagingQueues):
                    self.messagingQueues[senderIdentifier] = queue.Queue()
                
                threading.Thread(target = self.ListenForMessages, args=(peerSocket, senderIdentifier, sBytes, AESKey, senderPublicKey), daemon=True).start()
                threading.Thread(target=self.MessageSender, args=(senderIdentifier,)).start()
        except Exception as e:
            self.logger.error(f"Error {e} in HandleIncomingConnection", exc_info=True)
        finally:
            conn.close()
    
    def MessageSender(self, recipientIdentifier):
        messageQueue = self.messagingQueues[recipientIdentifier]
        while True:
            message = messageQueue.get()
            messageData = message[0].encode()
            messageType = message[1]
            self.logger.warning(f"Now Sending {messageData} to {recipientIdentifier}")
            self.logger.warning(f"sBytes check in MessageSender {self.activeSBytes[recipientIdentifier].hex()}")
            self.SendMessage(self.activeAESKeys[recipientIdentifier], self.activeSBytes[recipientIdentifier], recipientIdentifier, messageData, messageType)
    
    def SendMessage(self, AESKey, sBytes, recipientIdentifier, messageData, messageType="message"):
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            
            messagePayloadRaw = self.CalculateMessage(AESKey, messageData, sBytes, self.privateKey, messageType=messageType)
            messagePayload = json.dumps(messagePayloadRaw).encode()
            self.logger.debug(f"Message Payload Length : {len(messagePayload)}")
            self.logger.info("Sending padded payload of length " + str(len(messagePayload.ljust(self.messagePadLength, b'\0'))))
            with self.connectionLocks[recipientIdentifier]:
                outputSocket = self.openConnections[recipientIdentifier]
                self.logger.debug(f"AES KEY on sender : {AESKey.hex()}")
                self.logger.debug(f"Recipient Identifier in SendMessage is {recipientIdentifier}")
                self.logger.debug(f"Socket: {(outputSocket)}, {self.openConnections}, {outputSocket in self.openConnections.values()}")
                
                if outputSocket.fileno() == -1:
                    self.logger.error(f"Socket for {recipientIdentifier} is closed in SendMessage (fileno == -1)")
                    return
                
                outputSocket.send(messagePayload.ljust(self.messagePadLength, b"\0"))

            #Encrypting message with SQL
            #Encrypting the message with Fernet
            cipher = Fernet(self.fernetKey)
            messageFernet = cipher.encrypt(messageData)

            #Adding message to the SQL
            cursor.execute(f"INSERT INTO chat{recipientIdentifier} (timestamp, senderIdentifier, message, type) VALUES (?, ?, ?, ?)", (messagePayloadRaw["timestamp"], identifier, messageFernet, "message"))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error {e} in SendMessage", exc_info=True)
        finally:
            conn.close()
    
    def StartSession(self, otherIdentifier=None, host=None, port=None, isOnlineCheck=False, event=None):
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            
            if(host == None and port==None):
                host = self.knownUsers[otherIdentifier].host
                port = self.knownUsers[otherIdentifier].port
            
            self.logger.debug(f"Host : {host}, Port : {port}")
            
            try:
                outputSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                outputSocket.connect((host, port))            
            except OSError as e:
                if(isOnlineCheck):
                    self.logger.info(f"User {otherIdentifier} is not online : code {e.winerror} in StartSession")
                    event.set()
                    return None
                else:
                    self.logger.error(f"Error connecting to {identifier} at {host}:{port} : code {e.winerror} StartSession")
            
            #Choosing the DHE p,g and a
            p = self.GeneratePrime(self.DHEBitLength)
            g = self.GeneratePrime(self.DHEBitLength)
            a = self.GeneratePrime(self.DHEBitLength)
            
            self.logger.debug("FOUND P G a")
            
            #Computing A
            A = pow(g,a,p)
            
            self.logger.debug("FOUND A")
            
            #Generating p g and A payload
            payload = json.dumps({"p" : p, "g" : g, "A" : A}).encode()
            payload = payload.ljust(math.ceil(len(payload) / 256) * 256, b"\0")
            
            #Sending a session request and the length of the payload
            self.logger.debug(f"Length Of Payload On Sender Side : {len(payload)}")
            outputSocket.send(json.dumps({"type" : "sessionRequest", "identifier" : identifier ,"DHEPayloadLength" : len(payload), "displayName" : displayName}).encode().ljust(128, b"\0"))
            self.logger.debug("SENT REQUEST + DETAILS")
            
            response = json.loads(outputSocket.recv(128).rstrip(b"\0").decode())
            
            if(response["type"] != "sessionRequestAccept"):
                self.logger.debug("FAILED REQUEST")
                return
            
            otherIdentifier = response["identifier"] 
            
            if(response["keyRequest"] == True):
                #Sending public key
                publicKeyBytes = self.publicKey.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                
                self.logger.debug("Sending Key Request")
                
                
                outputSocket.send(json.dumps({"publicKey" : base64.b64encode(publicKeyBytes).decode(), "host" : outputSocket.getsockname()[0], "port" : self.incomingConnectionPort}).encode().ljust(128, b"\0"))
            
            if(otherIdentifier not in self.knownUsers):
                shouldRequestKey = True
            else:
                shouldRequestKey = False
            
            if(shouldRequestKey):
                outputSocket.send(json.dumps({"type" : "recipientPublicKeyRequest"}).encode().ljust(64, b"\0"))
                recipientPublicKeyDetails = json.loads(outputSocket.recv(256).rstrip(b"\0").decode())
                self.logger.debug(type(self.knownUsers))
                recipientPublicKey = base64.b64decode(recipientPublicKeyDetails["recipientPublicKey"])
                self.logger.debug("REQUESTING KEY IN StartSession")
                self.logger.debug(f"NEW knownUsers in StartSession : {self.knownUsers}")
                recipientHost = recipientPublicKeyDetails["host"]
                recipientPort = recipientPublicKeyDetails["port"]
            
                #Updating SQL
                cursor.execute("INSERT INTO savedUsers (identifier, publicKey, displayName, host, port) VALUES (?, ?, ?, ?, ?)", (otherIdentifier, recipientPublicKey, recipientPublicKeyDetails["displayName"], recipientHost, recipientPort))
                
                conn.commit()
                
                self.knownUsers[otherIdentifier] = PeerDetail(otherIdentifier, recipientPublicKey, recipientPublicKeyDetails["displayName"], recipientHost, recipientPort)
            else:
                outputSocket.send(json.dumps({"type" : "recipientPublicKeyNotNeeded"}).encode().ljust(64, b"\0"))
                self.logger.debug(f"ALREADY HAVE KEY FOR {otherIdentifier}")
                cursor.execute("SELECT * FROM savedUsers WHERE identifier = ?", (otherIdentifier,))
                recipientPublicKey = cursor.fetchone()[1]
            
            recipientPublicKey = ed25519.Ed25519PublicKey.from_public_bytes(recipientPublicKey)
            
            outputSocket.send(payload)
            self.logger.debug("SENT PAYLOAD")
            
            #Receiving B
            B = json.loads(outputSocket.recv(int(self.DHEBitLength / 2)).rstrip(b"\0").decode())["B"]
            
            #Finding s
            s = pow(B, a, p)
            
            sBytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")
            
            self.logger.info(f"FOUND sBYTES in StartSession : {len(sBytes)} {sBytes.hex()}")
            self.logger.debug(f"Other Identifier : {otherIdentifier}, Recipient Identifier : {otherIdentifier}")
            self.activeSBytes[otherIdentifier] = sBytes
            self.logger.debug(f"ActiveSBytes : {self.activeSBytes[otherIdentifier].hex()}")
            #Generating AES Key
            AESKey = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(sBytes)
            
            self.activeAESKeys[otherIdentifier] = AESKey
            
            #Avoiding SQL Injection - Only allow nums, letters and _s
            if(re.sub(r"\W+", "", otherIdentifier) != otherIdentifier):
                self.logger.error(f'RECIPIENT IDENTIFIER IS INVALID IN STARTSESSION - ATTEMPTED SQL INJECTION (ORG : {otherIdentifier})')
                return
            
            #Creating the SQL table
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS chat{otherIdentifier} (
                timestamp TEXT NOT NULL,
                senderIdentifier TEXT NOT NULL,
                message BLOB,
                type TEXT NOT NULL,
                extension TEXT,
                filePath TEXT UNIQUE,
                userFilename TEXT
            )
            ''')
            conn.commit()
            
            #Adding connection to known connections
            with self.openConnectionsLock:
                self.openConnections[otherIdentifier] = outputSocket
            
                self.logger.warning(f"(DELETE THIS) OPEN CONNECTIONS : {self.openConnections}")
            
            #Making a lock for this message
            if(otherIdentifier not in self.connectionLocks):
                self.connectionLocks[otherIdentifier] = threading.Lock()
            
            #Generating message queue
            if(otherIdentifier not in self.messagingQueues):
                self.messagingQueues[otherIdentifier] = queue.Queue()
            
            threading.Thread(target = peer.ListenForMessages, args=(outputSocket, otherIdentifier, sBytes, AESKey, recipientPublicKey), kwargs= {"event" : event},daemon=False).start()
            threading.Thread(target=self.MessageSender, args=(otherIdentifier,)).start()
            
            return outputSocket
        except Exception as e:
            self.logger.error(f"Error {e} in StartSession", exc_info=True)
        finally:
            conn.close()   
     
    def EndSession(self, otherUserIdentifier):
        with self.connectionLocks[otherUserIdentifier]:
            connectionSocket = self.openConnections[otherUserIdentifier]
            connectionSocket.send(json.dumps({"type" : "closeSocket"}).encode().ljust(self.messagePadLength, b"\0"))
            
        
    def CalculateMessage(self, AESKey, plaintext, sBytes, edPrivateKey, messageType="message"):
        try:
            nonce = os.urandom(12)
            aesGCM = AESGCM(AESKey)
            ciphertext = aesGCM.encrypt(nonce, plaintext, None)
            
            #HMAC - makes sure the data has not been tampered with, comes from someone with the correct key
            
            hmacTag = hmac.new(sBytes, nonce + ciphertext, hashlib.sha256).digest()
            
            #ED - signature
            signature = edPrivateKey.sign(plaintext)
            
            #Timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
           
            self.logger.debug(f"sBytes on CalculateMessage : {sBytes.hex()}") 
            self.logger.debug(f"HMAC on sender : {hmacTag.hex()}")
            self.logger.debug(f"Nonce on sender : {nonce.hex()}")
            self.logger.debug(f"Ciphertext in sender : {ciphertext.hex()}")
            return {
                "type" : messageType,
                "nonce": base64.b64encode(nonce).decode(), #Doing this because json.dumps doesnt like b""
                "hmacTag": base64.b64encode(hmacTag).decode(),
                "signature" : base64.b64encode(signature).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "timestamp" : timestamp
            }
        except Exception as e:
            self.logger.error(f"Error {e} in CalculateMessage", exc_info=True)
    
    def ReturnMessages(self, otherIdentifier, amount, sort, reversed):
        try:
            if(re.sub(r"\W+", "", otherIdentifier) != otherIdentifier): #Stopping SQL injection attack
                self.logger.error(f'SENDER IDENTIFIER IS INVALID IN RETURNMESSAGES - ATTEMPTED SQL INJECTION (ORG : {otherIdentifier})')
                return
            
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()

            if(sort == "asc"):
                cursor.execute(f"SELECT * FROM chat{otherIdentifier} ORDER BY timestamp ASC")
                self.logger.debug("ASC")
            else:
                cursor.execute(f"SELECT * FROM chat{otherIdentifier} ORDER BY timestamp DESC")
                self.logger.debug("DESC")
            if(int(amount) == 0):
                rows = cursor.fetchall()
            else:
                rows = cursor.fetchmany(amount)
            
            cipher = Fernet(self.fernetKey)
            
            rowsOutput = []
            for row in rows:
                if(row[3] == "message"):
                    rowsOutput.append([row[3], row[0], row[1], cipher.decrypt(row[2]).decode()])
                elif(row[3] == "file"):
                    rowsOutput.append([row[3], row[0], row[1], row[4], row[5], row[6]])
            
            if(reversed == "true" and sort=="asc") or (reversed=="false" and sort=="desc"):
                rowsOutput = rowsOutput[::-1] #Making sure its in the right order

            self.logger.debug(f"ROWS REVERSED: {rowsOutput}")

        except Exception as e:
            self.logger.error(f"Error {e} in ReturnMessages", exc_info=True)
        finally:
            conn.close()
            return rowsOutput

    def ReturnSavedUsers(self):
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            
            cursor.execute(f"SELECT * FROM savedUsers")
            rows = cursor.fetchall()

            rows = [[row[0], row[2]] for row in rows]
            
            conn.close()
            
            self.logger.debug(f"USERS : f{rows}")
           
            onlineUsers = [identifier for identifier in self.onlineUsersDict if self.onlineUsersDict[identifier]]
            return (rows, onlineUsers)
        except Exception as e:
            self.logger.error(f"Error {e} in ReturnSavedUsers", exc_info=True)

    def AddNewUser(self, host, port):
        try:
            
            #Making sure we dont know user
            for knownUser in self.knownUsers:
                user = self.knownUsers[knownUser]
                if(user.host == host) and (user.port == port):
                    return
            
            self.logger.debug("ADDING NEW USER")
            self.StartSession(host=host, port=port)
            
            for knownUser in self.knownUsers:
                user = self.knownUsers[knownUser]
                if(user.host == host) and (user.port == port):
                    self.EndSession(user.identifier)
                    self.logger.debug(f"SUCCESSFULLY ADDED {user.identifier}")
                    self.onlineUsersDict[user.identifier] = True
        except Exception as e:
            self.logger.error(f"Error {e} in AddNewUser", exc_info=True)

    def GetDetailsOfUser(self, userID):
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            
            cursor.execute(f"SELECT * FROM savedUsers WHERE identifier = ?", (userID,))
            row = cursor.fetchone()

            conn.close()
            return row
        except Exception as e:
            self.logger.error(f"Error {e} in GetDetailsOfUser", exc_info=True)

    def GeneratePrime(self, bitLength):
        while True:
            # Generate random odd number of desired bit length
            candidate = random.getrandbits(bitLength) | (1 << bitLength - 1) | 1
            if self.IsPrime(candidate):
                return candidate

    def IsPrime(self, n, k=40):
        #Miller - Rabin primality test
       
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d with d odd
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1

        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True


#FLASK
app = Flask(__name__, template_folder='src', static_folder='src')
app.config['SECRET_KEY'] = 'secret' #!TEMP - MAKE A BETTER KEY 
CORS(app)  # Allows cross-origin requests
socketio = SocketIO(app)

peer = Peer(socketioInstance=socketio)

peerDetailsFilename = f"Peer{identifier}Details.json"

#Making sure we have a peerDetailsFilename file
if not os.path.exists(peerDetailsFilename):
    with open(peerDetailsFilename, "w") as fileHandle:
        json.dump(
        {   "theme" : "Sea",
            "sendNotifications" : "true",
            "use12hFormat" : "false"
        }, fileHandle, indent=4) 

@app.route('/api/LoadPage/<page>')
def index(page):
    peer.logger.debug(f"page in index : {page}")
    return send_from_directory(app.template_folder, page) 

@app.route('/api/static/icons/<filename>')
def SendIcon(filename):
    return send_from_directory('src/icons', filename)

@app.route('/api/GetDetails', methods=['GET'])
def GetDetails():
    try:
        with open(peerDetailsFilename, "r") as fileHandle:
            details = json.load(fileHandle)
            return jsonify({
                "identifier" : identifier,
                "theme" : details["theme"],
                "sendNotifications" : details["sendNotifications"],
                "use12hFormat" : details["use12hFormat"],
                "publicKey" : peer.VisualisePublicKey(identifier),
                "displayName" : displayName,
                "maxMessageLength" : peer.messageLength
            })
        
    except Exception as e:
        peer.logger.error(f"Error {e} in GetDetails", exc_info=True)
        return jsonify({"Unexpected error - check logs"}), 500

@app.route('/api/GetSavedUsers', methods=['GET'])
def GetSavedUsers():
    try:
        users = peer.ReturnSavedUsers()
        return jsonify({"users" : users[0], "onlineUsers" : users[1]})
        
    except Exception as e:
        peer.logger.error(f"Error {e} in GetSavedUsers", exc_info=True)
        return jsonify({"Unexpected error - check logs"}), 500

@app.route('/api/GetMessages/<otherIdentifier>', methods=['GET'])
def GetMessages(otherIdentifier):
    try:
        peer.logger.debug(f"GetMessagesRaw : {otherIdentifier}")
        amount = int(request.args.get('amount', 0)) #Defaults to 0
        sort = request.args.get('sort', 'asc') #Defaults to ascending
        reversed = request.args.get('reversed', 'false') #Defaults to false
        peer.logger.debug(f"GetMessages : {otherIdentifier} {amount} {sort} {reversed}")
        
        return jsonify(peer.ReturnMessages(otherIdentifier, amount, sort, reversed))
    
    except Exception as e:
        peer.logger.error(f"Error {e} in GetMessages", exc_info=True)
        return jsonify({"Unexpected error - check logs"}), 500

@app.route('/api/GetThemes/', methods=['GET'])
def GetThemes():
    try:
        with open("Themes.json", "r") as fileHandle:
            themeData = json.load(fileHandle)
        return themeData
    
    except Exception as e:
        peer.logger.error(f"Error {e} in GetThemes", exc_info=True)
        return jsonify({"Unexpected error - check logs"}), 500

@app.route('/api/Post/SetSetting', methods=['POST'])
def SetSetting():
    content = request.json  # Get JSON from the request body
    key = content["key"]
    with open(peerDetailsFilename, "r") as fileHandle:
        details = json.load(fileHandle)
    details[key] = content["value"]
    with open(peerDetailsFilename, "w") as fileHandle:
        json.dump(details, fileHandle, indent=4)
        
    return jsonify({"status" : "success"})

@app.route('/api/GetDetailsOfOtherUser/<otherUserID>', methods=['GET'])
def GetDetailsOfOtherUser(otherUserID):
    details = peer.GetDetailsOfUser(otherUserID)
    return jsonify({
        "identifier" : details[0],
        "publicKey" :  peer.VisualisePublicKey(details[0]),
        "displayName" : details[2] 
    })
    
@app.route('/api/Post/SendMessageToUser/<otherUserID>', methods=['POST'])
def SendMessageToUser(otherUserID):
    content = request.json  # Get JSON from the request body
    
    message = content["message"]
    peer.logger.debug(f"MESSAGE TO SEND TO {otherUserID}: {message}")    
    
    peer.messagingQueues[otherUserID].put([message, "message"])
    peer.logger.debug("Added message to message Queue")

    return jsonify({"status" : "success"})

@app.route('/api/Post/ChangeSession', methods=['POST'])
def ChangeSession():
    content = request.json  # Get JSON from the request body
    identifier = content["identifier"]
    peer.logger.debug(f"Recieved Change Session Request For {identifier} : {content['type'].lower()}")
    if(identifier in peer.openConnections and content["type"].lower() == "end"):
        peer.logger.debug(f"Ending session with {identifier}")
        peer.EndSession(identifier)
    elif(identifier not in peer.openConnections) and (content["type"].lower() == "start"):
        peer.logger.debug(f"Starting session with {identifier}")
        peer.StartSession(identifier)
    return jsonify({"status" : "success"})

@app.route('/api/Post/AddNewUser', methods=['POST'])
def AddNewUser():
    content = request.json  # Get JSON from the request body
    host = content["host"]
    port = int(content["port"])
    
    peer.logger.debug("ADDING NEW USER")
    peer.AddNewUser(host=host, port=port)
    
    return jsonify({"status" : "success"})

@app.route("/api/Post/SendFile", methods=['POST'])
def SendFile():
    try:
        file = request.files.get("file")
        extension = request.form.get("extension") 
        filename = request.form.get("filename")
        otherIdentifier = request.form.get("otherIdentifier")  

        timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        binaryData = file.read()
        
        #Encrypting the data
        nonce = os.urandom(12)
        aesGCM = AESGCM(peer.activeAESKeys[otherIdentifier])
    
        totalChunks = math.ceil(len(binaryData) / peer.fileChunkSizeBytes) 

        #Using fernet to ensure security as a file cannot just be read
        cipher = Fernet(peer.fernetKey)
        ciphertextFernet= cipher.encrypt(binaryData)    
        os.makedirs(f"uploads{identifier}", exist_ok=True)
        with open(f"uploads{identifier}/{identifier}--{otherIdentifier}--{timestamp}.bin", "wb") as fileHandle:
            fileHandle.write(ciphertextFernet)

        peer.logger.debug(f"{peer.openConnections} {otherIdentifier} {peer.openConnections[otherIdentifier]}")
        otherUserConnection = peer.openConnections[otherIdentifier]
        otherUserConnection.send(json.dumps({"type" : "fileUploadNew", "identifier" : identifier, "fileExtension" : extension, "length" : len(binaryData), "timestamp" : timestamp, "userFilename" : filename}).encode().ljust(peer.messagePadLength, b"\0"))
        peer.filesBeingUploaded.append(FileUpload(identifier, otherIdentifier, extension, len(binaryData),timestamp,True,totalChunks,filename))
        peer.logger.debug(f"len(plaintext) : {len(binaryData)}")
        peer.logger.debug(f"Current file upload list : {peer.filesBeingUploaded}")
        
        for i in range(totalChunks):
            nonce = os.urandom(12)
            chunk = binaryData[i * peer.fileChunkSizeBytes : (i + 1) * peer.fileChunkSizeBytes]
            chunkEncrypted = aesGCM.encrypt(nonce, chunk, None)
            
            #HMAC - makes sure the data has not been tampered with, comes from someone with the correct key
            hmacTag = hmac.new(peer.activeSBytes[otherIdentifier], chunkEncrypted, hashlib.sha256).digest()
            #ED - signature
            signature = peer.privateKey.sign(chunk)
            
            otherUserConnection.send(json.dumps({"type" : "fileUploadChunk" , "chunkIndex" : i, "chunkLength" : len(chunkEncrypted), "hmacTag" : base64.b64encode(hmacTag).decode('utf-8'), "signature" : base64.b64encode(signature).decode('utf-8'), "nonce" : base64.b64encode(nonce).decode('utf-8')}).encode().ljust(peer.fileChunkHeaderSizeBytes, b"\0"))
            otherUserConnection.send(chunkEncrypted)
        otherUserConnection.send(json.dumps({"type" : "fileUploadEnd"}).encode().ljust(peer.fileChunkHeaderSizeBytes, b"\0"))
        
        conn = sqlite3.connect(peer.databaseName)
        cursor = conn.cursor()
        cursor.execute(f"INSERT INTO chat{otherIdentifier} (timestamp, senderIdentifier, type, extension, filePath, userFilename) VALUES (?, ?, ?, ?, ?, ?)", (timestamp, identifier, "file", extension, f"uploads{identifier}/{identifier}--{otherIdentifier}--{timestamp}.bin", filename))
        conn.commit()
        return {"status": "success"}
    except Exception as e:
        peer.logger.error(f"Error {e} in SendFile", exc_info=True)
    finally:
        conn.close()

@app.route('/api/GetFileData/<extension>/<path:filePath>', methods=['GET'])
def GetFileData(extension, filePath):
    try:
        filePath = filePath.replace("%20", " ")
        peer.logger.debug(f"filePath : {filePath}, extension : {extension}")
        with open(filePath, "rb") as fileHandle:
            encryptedBytes = fileHandle.read()
        cipher = Fernet(peer.fernetKey)
        fileBytes = cipher.decrypt(encryptedBytes)
        fileIO = io.BytesIO(fileBytes)
        mimeType, _ = mimetypes.guess_type("file." + extension)
        
        peer.logger.debug(f"MIME type : {mimeType}")
        if(mimeType and "image" in mimeType):
            image = Image.open(fileIO)
            
            if image.mode == 'RGBA':
                image = image.convert('RGB')
            
            if(request.args.get('shouldCrop', 'False').lower() == "true"):
                width, height = image.size
                minHeight = min(height, int(request.args.get("maxHeight", 256)))
                minWidth = min(width, int(request.args.get("maxWidth", 256)))
                
                peer.logger.debug(f"minHeight : {minHeight}, minWidth : {minWidth}")
                left = (width - minWidth) // 2
                top = (height - minHeight) // 2
                right = left + minWidth
                bottom = top + minHeight

                image = image.crop((left, top, right, bottom))
            
            if(request.args.get("shouldResize", "False").lower() == "true"):
                maxSize = (int(request.args.get("maxWidth", 256)), int(request.args.get("maxHeight", 256)))
                image.thumbnail(maxSize, Image.LANCZOS)
            
            fileIO = io.BytesIO()
            image.save(fileIO, format=image.format or "JPEG")
            fileIO.seek(0)
        
        return send_file(
            fileIO,
            mimetype= mimeType,
            as_attachment=False
        )
    except Exception as e:
        peer.logger.error(f"Error {e} in GetFileData", exc_info=True)
    
if __name__ == "__main__":
    #Starting Website
    frontendPort = int(input("FRONTEND PORT : "))
    peer.logger.debug("STARTING WEBSITE")
    threading.Thread(target = socketio.run, kwargs={"app" : app, "port": int(frontendPort), "debug": False}).start()
    
    peer.logger.debug("STARTING UP")
    peer.Start()
    threading.Thread(target = peer.WaitForIncomingRequests, daemon=False).start()