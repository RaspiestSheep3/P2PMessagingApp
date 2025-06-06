import socket
import threading
import logging
import colorlog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import random
import json
import math
import hmac, hashlib
import os
import base64

#!TEMP - MAKE BETTER SYSTEM FOR IDENTIFICATION
identifier = input("PEER IDENTIFIER : ")

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
        details = json.loads(peerSocket.recv(128).rstrip(b"\0").decode())
        self.logger.info(f"RECIEVED {details}")
        
        if(details["type"] == "sessionRequest"):
            incomingPayloadLength = details["DHEPayloadLength"]
            peerSocket.send(json.dumps({"type" : "sessionRequestAccept"}).encode().ljust(64, b"\0"))
            
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
            
            #Receiving message
            message = json.loads(peerSocket.recv(self.messagePadLength).rstrip(b"\0").decode())
            nonce = base64.b64decode(message["nonce"])
            hmacTag = base64.b64decode(message["hmacTag"])
            ciphertext = base64.b64decode(message["ciphertext"])
            
            #HMAC test   
            expectedHmacTag = hmac.new(sBytes, ciphertext, hashlib.sha256).digest()
            if hmac.compare_digest(hmacTag, expectedHmacTag):
                self.logger.info("HMAC TAG CORRECT")
            else:
                self.logger.error("HMAC TAG INCORRECT - DATA TAMPERED OR FORGED")
                
            #Decrypting ciphertext
            aesGCM = AESGCM(AESKey)
            plaintext = aesGCM.decrypt(nonce, ciphertext, None).decode()
            
            self.logger.info(f"RECIEVED PLAINTEXT {plaintext}")
    
    def StartSession(self):
        #TODO
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
            
            #Sending p g and A
            payload = json.dumps({"p" : p, "g" : g, "A" : A}).encode()
            
            #Sending a session request and the length of the payload
            outputSocket.send(json.dumps({"type" : "sessionRequest", "DHEPayloadLength" : math.ceil(len(payload) / 256) * 256}).encode().ljust(128, b"\0"))
            self.logger.debug("SENT REQUEST + DETAILS")
            
            response = json.loads(outputSocket.recv(64).rstrip(b"\0").decode())
            
            if(response["type"] != "sessionRequestAccept"):
                self.logger.debug("FAILED REQUEST")
                return
            
            #Sending the payload
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
            
            #Sending message
            #TODO : make proper messaging system
            messagePayload = json.dumps(self.CalculateMessage(AESKey, b"TEST MESSAGE 123", sBytes)).encode()
            self.logger.debug(f"Message Payload Length : {len(messagePayload)}")
            
            outputSocket.send(messagePayload.ljust(self.messagePadLength, b"\0"))
            
            
    def CalculateMessage(self, AESKey, plaintext, sBytes):
        nonce = os.urandom(12)
        aesGCM = AESGCM(AESKey)
        ciphertext = aesGCM.encrypt(nonce, plaintext, None)
        
        #HMAC - makes sure the data has not been tampered with, comes from someone with the correct key
        
        hmacTag = hmac.new(sBytes, ciphertext, hashlib.sha256).digest()
        
        return {
        "nonce": base64.b64encode(nonce).decode(), #Doing this because json.dumps doesnt like b""
        "hmacTag": base64.b64encode(hmacTag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

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

if __name__ == "__main__":
    peer = Peer()
    peer.logger.debug("STARTING UP")
    peer.Start()
    threading.Thread(target = peer.WaitForIncomingRequests, daemon=False).start()
    shouldSend = input("SHOULD SEND?")
    if(shouldSend == "Y"):
        peer.StartSession()