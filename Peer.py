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
from flask import Flask, jsonify, Response, request
from flask_cors import CORS
from datetime import datetime
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

class Peer():
    def __init__ (self, incomingConnectionHost="0.0.0.0", incomingConnectionPort = incomingConnectionPortGlobal):
        self.connections = []
        self.incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.incomingConnectionHost = incomingConnectionHost
        self.incomingConnectionPort = incomingConnectionPort
        self.connectedAddrs = []
        self.activeConnectionThreads = []
        self.DHEBitLength = 512 #TODO : Consider 1024 in the future
        self.messagePadLength = 2048
        self.messageLength = 1900
        self.knownUsers = []
        self.databaseName = f"Peer{identifier}Database.db"
        self.publicKey = None
        self.privateKey = None
        self.fernetKey = None
        self.hashedIdentifier =  hashlib.sha256(identifier.encode()).hexdigest()
        self.appName = "P2PMessagingApp"
        
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
        
    #Public Key Visualiser
    def VisualisePublicKey(self, userIdentifier):
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
            
    def WaitForIncomingRequests(self):
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
        
    
    def HandleIncomingConnection(self, peerSocket):
        #TODO
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
                cursor.execute("INSERT INTO savedUsers (identifier, publicKey, displayName) VALUES (?, ?, ?)", (senderIdentifier, senderPublicKey, "TIMMY"))
                #!"TIMMY" IS TEMP - TO CODE A BETTER SOLN.
                
                conn.commit()
                self.knownUsers[senderPublicKey] = senderPublicKey #Adding to dict
            else:
                self.logger.debug(f"ALREADY HAVE KEY FOR {senderIdentifier}")
                cursor.execute("SELECT * FROM savedUsers WHERE identifier = ?", (senderIdentifier,))
                senderPublicKey = cursor.fetchone()[1]
            
            senderPublicKey = ed25519.Ed25519PublicKey.from_public_bytes(senderPublicKey)
            
            payload = json.loads(peerSocket.recv(incomingPayloadLength).decode())
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
                self.logger.error(f"SENDER IDENTIFIER IS INVALID - ATTEMPTED SQL INJECTION")
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
            
            #Receiving message
            message = json.loads(peerSocket.recv(self.messagePadLength).rstrip(b"\0").decode())
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
    
        conn.close()
    
    def StartSession(self):
        #TODO
        conn = sqlite3.connect(self.databaseName)
        cursor = conn.cursor()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as outputSocket:
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
            
            #Sending a session request and the length of the payload
            outputSocket.send(json.dumps({"type" : "sessionRequest", "identifier" : identifier ,"DHEPayloadLength" : math.ceil(len(payload) / 256) * 256}).encode().ljust(128, b"\0"))
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
            outputSocket.send(payload)
            self.logger.debug("SENT PAYLOAD")
            
            #Receiving B
            B = json.loads(outputSocket.recv(int(self.DHEBitLength / 2)).rstrip(b"\0").decode())["B"]
            
            #Finding s
            s = pow(B, a, p)
            
            sBytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")
            
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
                self.logger.error(f"RECIPIENT IDENTIFIER IS INVALID - ATTEMPTED SQL INJECTION")
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
            
            #Sending message
            #TODO : make proper messaging system
            messageData = b"TEST MESSAGE 123"
            messagePayloadRaw = self.CalculateMessage(AESKey, messageData, sBytes, self.privateKey)
            messagePayload = json.dumps(messagePayloadRaw).encode()
            self.logger.debug(f"Message Payload Length : {len(messagePayload)}")
            
            outputSocket.send(messagePayload.ljust(self.messagePadLength, b"\0"))

            #Encrypting message with SQL
            #Encrypting the message with Fernet
            cipher = Fernet(self.fernetKey)
            messageFernet = cipher.encrypt(messageData)

            #Adding message to the SQL
            cursor.execute(f"INSERT INTO chat{recipientIdentifier} (timestamp, senderIdentifier, message) VALUES (?, ?, ?)", (messagePayloadRaw["timestamp"], identifier, messageFernet))
            conn.commit()
            
        conn.close()   
            
    def CalculateMessage(self, AESKey, plaintext, sBytes, edPrivateKey):
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
    
    def ReturnMessages(self, otherIdentifier):
        conn = sqlite3.connect(self.databaseName)
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT * FROM chat{otherIdentifier}")
        rows = cursor.fetchall()
        
        cipher = Fernet(self.fernetKey)
        
        rows = [[row[0], row[1], cipher.decrypt(row[2]).decode()] for row in rows]
        
        conn.close()
        return rows

    def ReturnSavedUsers(self):
        conn = sqlite3.connect(self.databaseName)
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT * FROM savedUsers")
        rows = cursor.fetchall()

        rows = [[row[0], row[2]] for row in rows]
        
        conn.close()
        
        self.logger.debug(f"USERS : f{rows}")
        return rows

    def GetDetailsOfUser(self, userID):
        conn = sqlite3.connect(self.databaseName)
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT * FROM savedUsers WHERE identifier = ?", (userID,))
        row = cursor.fetchone()

        conn.close()
        return row

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

peer = Peer()

#FLASK
app = Flask(__name__)
CORS(app)  # Allows cross-origin requests

peerDetailsFilename = f"Peer{identifier}Details.json"

#Making sure we have a peerDetailsFilename file
if not os.path.exists(peerDetailsFilename):
    with open(peerDetailsFilename, "w") as fileHandle:
        json.dump({"theme" : ""}, fileHandle, indent=4)

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
                "publicKey" : base64.b64encode(publicKeyDisplay).decode(),
                "displayName" : displayName
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
        return jsonify(peer.ReturnMessages(otherIdentifier))
    
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

@app.route('/api/Post/SetTheme', methods=['POST'])
def SetTheme():
    content = request.json  # Get JSON from the request body
    with open(peerDetailsFilename, "r") as fileHandle:
        details = json.load(fileHandle)
    details["theme"] = content["newTheme"]
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

if __name__ == "__main__":
    #Starting Website
    frontendPort = int(input("FRONTEND PORT : "))
    peer.logger.debug("STARTING WEBSITE")
    threading.Thread(target = app.run, kwargs={"port": int(frontendPort), "debug": False}).start()
    
    peer.logger.debug("STARTING UP")
    peer.Start()
    threading.Thread(target = peer.WaitForIncomingRequests, daemon=False).start()
    
    #Key visualiser
    keyToVisualise = input("Key To Visualise : ")
    if(keyToVisualise.strip() != ""):
        peer.logger.info(peer.VisualisePublicKey(keyToVisualise))
    
    shouldSend = input("SHOULD SEND?")
    if(shouldSend == "Y"):
        peer.StartSession()