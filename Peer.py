import socket
import threading
import logging
import colorlog

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
        self.generalLogHandler = logging.FileHandler(f"Peer{identifier}General.log")
        self.generalLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.generalLogHandler.setLevel(logging.DEBUG) 

        #Error handler
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
        messageRaw = peerSocket.recv(2048).decode()
        print(messageRaw)
    
    def SendMessage(self):
        #TODO
        port = int(input("LISTENER PORT"))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as outputSocket:
            outputSocket.connect(("127.0.0.1", port))
            outputSocket.send("ABC".encode())

if __name__ == "__main__":
    peer = Peer()
    peer.logger.debug("STARTING UP")
    peer.Start()
    threading.Thread(target = peer.WaitForIncomingRequests, daemon=False).start()
    shouldSend = input("SHOULD SEND?")
    if(shouldSend == "Y"):
        peer.SendMessage()