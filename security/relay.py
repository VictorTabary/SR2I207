import socket
import time
from threading import Thread

import ecies
import requests
from secp256k1 import PrivateKey

from security.utils import *

ANNOUNCE_DELAY = 1*60 # seconds
ANNOUNCE_URL = "http://localhost:8080"


class CircuitNode:

    def __init__(self, conn, addr, server):
        self.conn = conn
        self.addr = addr
        self.server = server
        self.stop_threads = False
        self.from_addr = None
        self.to_addr = None
        self.aes_key_to = None
        self.aes_key_back = None

        self.sock_to = None

    def close(self):
        self.stop_threads = True
        pass # todo
        """
        for s in self.socks:
            s.shutdown(socket.SHUT_RDWR); s.close()
            """

    def handle_request(self):
        print('Connected by', self.addr)

        # utilisés seulement si extrémité
        aes_node_key = b''
        EXTREMITY = False
        receiving_keys = []
        nb_keys = 0
        isSetUp = False

        while True and self.stop_threads == False:
            try:
                data = self.conn.recv(2048)
                if data:
                    frame = pickle.loads(data)
                    print(frame)
                    if frame["action"] == "key_establishment" and not EXTREMITY:
                        message = pickle.loads(ecies.decrypt(self.server.privkey, frame["enc_message"]))

                        dest = message['info']
                        if dest == 'aller':  # cas d'un noeud intermédiaire et de clef aller
                            self.aes_key_to = message['m']
                            self.from_addr = self.addr
                            print("\nCLE ALLER:", self.aes_key_to, '\n')

                        elif "destination" in dest:
                            nb_keys = int(dest.split(',')[1])
                            EXTREMITY = True    # pour gérer le cas spécial où on est extrémité de la connexion
                            aes_node_key = message['m']
                            self.from_addr = self.addr
                            print("\nCLE DU NOEUD:", aes_node_key, '\n')

                        else: # cas d'un noeud intermédiaire et de clef retour
                            aes_key_back = message['m']
                            self.to_addr = dest.split(',')[1].split(':')
                            self.sock_to = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                self.sock_to.connect((self.to_addr[0], int(self.to_addr[1])))
                            except:
                                print("Can't contact the next node")
                            print("\nCLE RETOUR:", aes_key_back, '\n')

                    elif EXTREMITY and not isSetUp and frame["action"] == "key_establishment":
                        message = pickle.loads(decrypt(frame["enc_message"], aes_node_key))
                        receiving_keys.append(message['m'])

                        if len(receiving_keys) == nb_keys:
                            isSetUp = True

                            print('\n', receiving_keys)
                            print("je suis une extrémité de la connexion (mais je ne suis pas implémenté pour le moment)\n")
                            print("maintenant il faut continuer le programme monsieur svp")

                    # pour le relai
                    elif frame["action"] == "relay":
                        decr_message = decrypt(frame["enc_message"], self.aes_key_to)
                        send_message(self.sock_to, decr_message)

                    self.conn.send(b"ACK")

            except socket.error as e:
                print(e)
                print(f"An error occured in the connection from {self.addr}")
                break




class NodeServer:
    def __init__(self, port):
        self.port = port

        self.key = PrivateKey()
        #self.privkey = "0x" + self.key.serialize()  # hexa
        #self.pubkey = self.key.pubkey.serialize()   # pas hexa
        self.privkey = base64.b64decode(b'AQcx++axCPTh3xOmYC8IzUSrrgynvVarDp+2fZj/wf4=').hex()
        self.pubkey = base64.b64decode(b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS')

        self.circuits = []

    def __str__(self):
        return f"Node at address {self.ip} with public key \n{self.key}."

    def close(self):
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()
        for circuit in self.circuits:
            circuit.close()

    def announce_to_relay(self):
        while True:
            requests.get(ANNOUNCE_URL+f"/relays/add-myself/{self.port}/{base64.b64encode(self.pubkey).decode()}")
            time.sleep(ANNOUNCE_DELAY)

    def start(self):
        # déclaration périodique au serveur public-relay-list
        Thread(target=self.announce_to_relay).start()

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('0.0.0.0', self.port))
        self.s.listen()

        while True:
            try:
                conn, addr = self.s.accept()
                circuit = CircuitNode(conn, addr, self)
                self.circuits.append(circuit)
                t = Thread(target=circuit.handle_request)
                t.start()
            except Exception as e:
                self.close()
                print("Socket is dead :",e)
                break