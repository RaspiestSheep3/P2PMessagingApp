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
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_socketio import SocketIO
from flask_cors import CORS
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

#!TEMP 
from time import sleep

#!TEMP - MAKE BETTER SYSTEM FOR IDENTIFICATION
identifier = input("PEER IDENTIFIER : ")

#!TEMP - MAKE BETTER SYSTEM FOR DISPLAY NAMES
displayName = input("DISPLAY NAME : ")

#!TEMP - MAKE BETTER WAY TO SET LISTEN PORT
incomingConnectionPortGlobal = int(input("INCOMING CONNECTION PORT : "))

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
        self.messageLength = 1800 #A bit less than 4x bcs with UTF8 we can use 4B/char, and we need some size for overhead stuff
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
            self.logger.info("SERVER STARTED UP")
            
            #SQL
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS savedUsers (
                    identifier STRING NOT NULL UNIQUE,
                    publicKey BLOB NOT NULL,
                    displayName TEXT NOT NULL
                )
            ''')

            cursor.execute("SELECT * FROM savedUsers")
            rows = cursor.fetchall()
            self.knownUsers = {row[0] : row[1] for row in rows}

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
            
            #!TEMP
            self.logger.warning(f"FERNET KEY (DELETE THIS) : {self.fernetKey}")
            self.logger.warning(f"KNOWN USERS (DELETE THIS) : {self.knownUsers}")
            
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
                key = (self.knownUsers[userIdentifier]).hex()
            
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
        
    def ListenForMessages(self, peerSocket, senderIdentifier, sBytes, AESKey, senderPublicKey):
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            while True:
                #with self.connectionLocks[senderIdentifier]:
                self.logger.debug(f"Sender Identifier in ListenForMessages is {senderIdentifier}")
                
                if peerSocket.fileno() == -1: #Checks if the connections open
                    self.logger.error(f"{senderIdentifier} socket is closed")
                    return
                
                messageRaw = peerSocket.recv(self.messagePadLength)
                if(messageRaw != b""):
                    #self.logger.debug(f"messageRaw in ListenForMessages : {messageRaw}")
                    message = json.loads(messageRaw.rstrip(b"\0").decode())
                    self.logger.debug(f"message in ListenForMessages : {message}")
                    nonce = base64.b64decode(message["nonce"])
                    hmacTag = base64.b64decode(message["hmacTag"])
                    signature = base64.b64decode(message["signature"])
                    ciphertext = base64.b64decode(message["ciphertext"])
                    timestamp = message["timestamp"]
                    
                    #HMAC test   
                    expectedHmacTag = hmac.new(sBytes, ciphertext, hashlib.sha256).digest()
                    if hmac.compare_digest(hmacTag, expectedHmacTag):
                        self.logger.info("HMAC TAG CORRECT")
                    else:
                        self.logger.error("HMAC TAG INCORRECT - DATA TAMPERED OR FORGED")
                        return
                        
                    #Decrypting ciphertext
                    aesGCM = AESGCM(AESKey)
                    plaintext = aesGCM.decrypt(nonce, ciphertext, None).decode()
                    
                    #Signature test
                    try:
                        self.logger.warning(f"SIGNATURE (DELETE THIS) : {senderPublicKey} {type(senderPublicKey)}")
                        senderPublicKey.verify(signature, plaintext.encode())
                    except InvalidSignature:
                        self.logger.critical(f"INVALID SIGNATURE - DO NOT TRUST")
                        return
                    
                    self.logger.info(f"RECIEVED PLAINTEXT {plaintext} which was sent at {timestamp}")
                    
                    #Encrypting the message with Fernet
                    cipher = Fernet(self.fernetKey)
                    messageFernet = cipher.encrypt(plaintext.encode())
                    
                    #Adding message to the SQL
                    cursor.execute(f"INSERT INTO chat{senderIdentifier} (timestamp, senderIdentifier, message) VALUES (?, ?, ?)", (timestamp, senderIdentifier, messageFernet))
                    conn.commit()
                    
                    #Alerting frontend about the new message
                    socketio.emit("newMessageIncoming", {
                        "timestamp" : timestamp,
                        "senderIdentifier" : senderIdentifier,
                        "message" : plaintext
                    })
                    
        except Exception as e:
            self.logger.error(f"Error {e} in ListenForMessages", exc_info=True)
        finally:
            conn.close()
    
    def HandleIncomingConnection(self, peerSocket):
        #TODO
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
                    senderPublicKey = json.loads(peerSocket.recv(128).rstrip(b"\0").decode())["publicKey"]
                    senderPublicKey = base64.b64decode(senderPublicKey)
                    
                    #Updating SQL
                    cursor.execute("INSERT INTO savedUsers (identifier, publicKey, displayName) VALUES (?, ?, ?)", (senderIdentifier, senderPublicKey, details["displayName"]))
                    
                    conn.commit()
                    self.knownUsers[senderPublicKey] = senderPublicKey #Adding to dict
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
                    
                    peerSocket.send(json.dumps({"type" : "recipientPublicKeyResponse", "recipientPublicKey" : base64.b64encode(selfPublicKey).decode(), "displayName" : displayName}).encode().ljust(256, b"\0"))
                
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
                
                self.logger.info("FOUND sBYTES in HandleIncomingConnection")
                
                #Generating AES Key
                AESKey = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                    backend=default_backend()
                ).derive(sBytes)
                
                #Avoiding SQL Injection - Only allow nums, letters and _s
                if(re.sub(r"\W+", "", senderIdentifier) != senderIdentifier):
                    self.logger.error(f'SENDER IDENTIFIER IS INVALID IN HANDLEINCOMINGCONNECTION - ATTEMPTED SQL INJECTION (ORG : {senderIdentifier})')
                    return
                
                #Creating the SQL table
                cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS chat{senderIdentifier} (
                    timestamp TEXT NOT NULL,
                    senderIdentifier TEXT NOT NULL,
                    message TEXT NOT NULL
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
                threading.Thread(target=self.MessageSender, args=(AESKey, sBytes, peerSocket, senderIdentifier)).start()
        except Exception as e:
            self.logger.error(f"Error {e} in HandleIncomingConnection", exc_info=True)
        finally:
            conn.close()
    
    def MessageSender(self, AESKey, sBytes, outputSocket, recipientIdentifer):
        messageQueue = self.messagingQueues[recipientIdentifer]
        while True:
            messageData = messageQueue.get().encode()
            self.logger.warning(f"Now Sending {messageData} to {recipientIdentifer}")
            self.SendMessage(AESKey, sBytes, outputSocket, recipientIdentifer, messageData)
    
    def SendMessage(self, AESKey, sBytes, outputSocket, recipientIdentifier, messageData):
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            
            messagePayloadRaw = self.CalculateMessage(AESKey, messageData, sBytes, self.privateKey)
            messagePayload = json.dumps(messagePayloadRaw).encode()
            self.logger.debug(f"Message Payload Length : {len(messagePayload)}")
            self.logger.info("Sending padded payload of length " + str(len(messagePayload.ljust(self.messagePadLength, b'\0'))))
            with self.connectionLocks[recipientIdentifier]:
                self.logger.debug(f"Recipient Identifier in SendMessage is {recipientIdentifier}")
                outputSocket.send(messagePayload.ljust(self.messagePadLength, b"\0"))

            #Encrypting message with SQL
            #Encrypting the message with Fernet
            cipher = Fernet(self.fernetKey)
            messageFernet = cipher.encrypt(messageData)

            #Adding message to the SQL
            cursor.execute(f"INSERT INTO chat{recipientIdentifier} (timestamp, senderIdentifier, message) VALUES (?, ?, ?)", (messagePayloadRaw["timestamp"], identifier, messageFernet))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error {e} in SendMessage", exc_info=True)
        finally:
            conn.close()
    
    def StartSession(self):
        #TODO
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            outputSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            port = int(input("LISTENER PORT"))   
            outputSocket.connect(("127.0.0.1", port))            
            
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
            
            recipientIdentifier = response["identifier"] 
            
            if(response["keyRequest"] == True):
                #Sending public key
                publicKeyBytes = self.publicKey.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                
                self.logger.debug("Sending Key Request")
                
                
                outputSocket.send(json.dumps({"publicKey" : base64.b64encode(publicKeyBytes).decode()}).encode().ljust(128, b"\0"))
            
            if(recipientIdentifier not in self.knownUsers):
                shouldRequestKey = True
            else:
                shouldRequestKey = False
            
            if(shouldRequestKey):
                outputSocket.send(json.dumps({"type" : "recipientPublicKeyRequest"}).encode().ljust(64, b"\0"))
                recipientPublicKeyDetails = json.loads(outputSocket.recv(256).rstrip(b"\0").decode())
                self.logger.debug(type(self.knownUsers))
                recipientPublicKey = base64.b64decode(recipientPublicKeyDetails["recipientPublicKey"])
                self.knownUsers[recipientIdentifier] = recipientPublicKey
                self.logger.debug("REQUESTING KEY IN StartSession")
                self.logger.debug(f"NEW knownUsers in StartSession : {self.knownUsers}")
            
                #Updating SQL
                cursor.execute("INSERT INTO savedUsers (identifier, publicKey, displayName) VALUES (?, ?, ?)", (recipientIdentifier, recipientPublicKey, recipientPublicKeyDetails["displayName"]))
                
                conn.commit()
            else:
                outputSocket.send(json.dumps({"type" : "recipientPublicKeyNotNeeded"}).encode().ljust(64, b"\0"))
                self.logger.debug(f"ALREADY HAVE KEY FOR {recipientIdentifier}")
                cursor.execute("SELECT * FROM savedUsers WHERE identifier = ?", (recipientIdentifier,))
                recipientPublicKey = cursor.fetchone()[1]
            
            recipientPublicKey = ed25519.Ed25519PublicKey.from_public_bytes(recipientPublicKey)
            
            outputSocket.send(payload)
            self.logger.debug("SENT PAYLOAD")
            
            #Receiving B
            B = json.loads(outputSocket.recv(int(self.DHEBitLength / 2)).rstrip(b"\0").decode())["B"]
            
            #Finding s
            s = pow(B, a, p)
            
            sBytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")
            
            self.logger.info("FOUND sBYTES in HandleIncomingConnection")
            
            #Generating AES Key
            AESKey = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(sBytes)
            
            #Avoiding SQL Injection - Only allow nums, letters and _s
            if(re.sub(r"\W+", "", recipientIdentifier) != recipientIdentifier):
                self.logger.error(f'RECIPIENT IDENTIFIER IS INVALID IN STARTSESSION - ATTEMPTED SQL INJECTION (ORG : {recipientIdentifier})')
                return
            
            #Creating the SQL table
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS chat{recipientIdentifier} (
                timestamp TEXT NOT NULL,
                senderIdentifier TEXT NOT NULL,
                message BLOB NOT NULL
            )
            ''')
            conn.commit()
            
            #Adding connection to known connections
            with self.openConnectionsLock:
                self.openConnections[recipientIdentifier] = outputSocket
            
                self.logger.warning(f"(DELETE THIS) OPEN CONNECTIONS : {self.openConnections}")
            
            #Making a lock for this message
            if(recipientIdentifier not in self.connectionLocks):
                self.connectionLocks[recipientIdentifier] = threading.Lock()
            
            #Generating message queue
            if(recipientIdentifier not in self.messagingQueues):
                self.messagingQueues[recipientIdentifier] = queue.Queue()
            
            threading.Thread(target = peer.ListenForMessages, args=(outputSocket, recipientIdentifier, sBytes, AESKey, recipientPublicKey), daemon=False).start()
            threading.Thread(target=self.MessageSender, args=(AESKey, sBytes, outputSocket, recipientIdentifier)).start()
        except Exception as e:
            self.logger.error(f"Error {e} in StartSession", exc_info=True)
        finally:
            conn.close()   
            
    def CalculateMessage(self, AESKey, plaintext, sBytes, edPrivateKey):
        try:
            nonce = os.urandom(12)
            aesGCM = AESGCM(AESKey)
            ciphertext = aesGCM.encrypt(nonce, plaintext, None)
            
            #HMAC - makes sure the data has not been tampered with, comes from someone with the correct key
            
            hmacTag = hmac.new(sBytes, ciphertext, hashlib.sha256).digest()
            
            #ED - signature
            signature = edPrivateKey.sign(plaintext)
            
            #Timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            return {
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
            
            rows = [[row[0], row[1], cipher.decrypt(row[2]).decode()] for row in rows]
            
            if(reversed == "true" and sort=="asc") or (reversed=="false" and sort=="desc"):
                rows = rows[::-1] #Making sure its in the right order

            self.logger.debug(f"ROWS REVERSED: {rows}")

        except Exception as e:
            self.logger.error(f"Error {e} in ReturnMessages", exc_info=True)
        finally:
            conn.close()
            return rows

    def ReturnSavedUsers(self):
        try:
            conn = sqlite3.connect(self.databaseName)
            cursor = conn.cursor()
            
            cursor.execute(f"SELECT * FROM savedUsers")
            rows = cursor.fetchall()

            rows = [[row[0], row[2]] for row in rows]
            
            conn.close()
            
            self.logger.debug(f"USERS : f{rows}")
            return rows
        except Exception as e:
            self.logger.error(f"Error {e} in ReturnSavedUsers", exc_info=True)

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
        publicKeyDisplay = peer.publicKey.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
        
        with open(peerDetailsFilename, "r") as fileHandle:
            details = json.load(fileHandle)
            return jsonify({
                "identifier" : identifier,
                "theme" : details["theme"],
                "sendNotifications" : details["sendNotifications"],
                "use12hFormat" : details["use12hFormat"],
                "publicKey" : base64.b64encode(publicKeyDisplay).decode(),
                "displayName" : displayName,
                "maxMessageLength" : peer.messageLength
            })
        
    except Exception as e:
        peer.logger.error(f"Error {e} in GetDetails", exc_info=True)
        return jsonify({"Unexpected error - check logs"}), 500

@app.route('/api/GetSavedUsers', methods=['GET'])
def GetSavedUsers():
    try:
        return jsonify(peer.ReturnSavedUsers())
    
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
    detailsKey = ed25519.Ed25519PublicKey.from_public_bytes(details[1])
    keyBytes = detailsKey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return jsonify({
        "identifier" : details[0],
        "publicKey" : base64.b64encode(keyBytes).decode(),
        "displayName" : details[2] 
    })
    
@app.route('/api/Post/SendMessageToUser/<otherUserID>', methods=['POST'])
def SendMessageToUser(otherUserID):
    content = request.json  # Get JSON from the request body
    
    message = content["message"]
    peer.logger.debug(f"MESSAGE TO SEND TO {otherUserID}: {message}")    
    
    peer.messagingQueues[otherUserID].put(message)
    peer.logger.debug("Added message to message Queue")

    return jsonify({"status" : "success"})

if __name__ == "__main__":
    #Starting Website
    frontendPort = int(input("FRONTEND PORT : "))
    peer.logger.debug("STARTING WEBSITE")
    threading.Thread(target = socketio.run, kwargs={"app" : app, "port": int(frontendPort), "debug": False}).start()
    
    peer.logger.debug("STARTING UP")
    peer.Start()
    threading.Thread(target = peer.WaitForIncomingRequests, daemon=False).start()
    
    #Key visualiser
    keyToVisualise = input("Key To Visualise : ")
    if(keyToVisualise.strip() != ""):
        peer.logger.info(peer.VisualisePublicKey(keyToVisualise))
    
    shouldSend = input("SHOULD START SESSION?")
    if(shouldSend == "Y"):
        peer.StartSession()