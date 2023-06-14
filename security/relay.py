import socket
import time
from threading import Thread

import ecies
import requests
from secp256k1 import PrivateKey

from security.utils import *

ANNOUNCE_DELAY = 1 * 60  # seconds
ANNOUNCE_URL = "http://localhost:8080"
PACKET_SIZE = 2048

class ExtremityHandler:
    def __init__(self, circuit):
        self.circuit = circuit

    def handle_message(self, raw_message):
        pass

class RelayHandler:
    def __init__(self, circuit):
        self.circuit = circuit
        self.thread = None

    def handle_message(self, raw_message):
        #elif frame["action"] == "relay":
        decr_message = decrypt(raw_message, self.circuit.aes_key_to)
        send_message(self.circuit.sock_to, decr_message)

    def start_reverse_relay(self):

        def handle_reverse():
            while True:
                raw_data = self.circuit.sock_to.recv(PACKET_SIZE)
                self.circuit.sock_to.send(b"ACK")
                if raw_data != b'ACK':
                    data = pickle.loads(raw_data)["enc_message"]
                    decr_message = decrypt(data, self.circuit.aes_key_from)
                    send_message(self.circuit.sock_from, decr_message)

        self.thread = Thread(target=handle_reverse)
        self.thread.start()


class CircuitNode:

    def __init__(self, conn, addr, server):


        self.messageHandler = None
        self.addr = addr
        self.server = server
        self.stop_threads = False
        self.from_addr = None
        self.to_addr = None
        self.aes_key_to = None
        self.aes_key_back = None

        self.relay_thread = None

        # from/to à comprendre dans le sens de l'établissement de la connexion
        self.sock_from = conn
        self.sock_to : socket.socket = None # utilisé uniquement si on est pas une extrémité

    def close(self):
        self.stop_threads = True
        pass  # todo
        """
        for s in self.socks:
            s.shutdown(socket.SHUT_RDWR); s.close()
            """

    def handle_request(self):
        print('Connected by', self.addr)

        # utilisés seulement si extrémité

        aes_node_key = b''
        EXTREMITY = False
        nb_keys = 0
        isSetUp = False
        receiving_keys = []

        while True and self.stop_threads == False:
            try:
                data = self.sock_from.recv(2048)
                if data and data != b'ACK':
                    frame = pickle.loads(data)
                    print(frame)

                    raw_message = frame["enc_message"]
                    if not EXTREMITY and frame["action"] == "key_establishment":
                        message = pickle.loads(ecies.decrypt(self.server.privkey, raw_message))

                        dest = message['info']
                        if dest == 'aller':  # cas d'un noeud intermédiaire et de clef aller
                            self.aes_key_to = message['m']
                            self.from_addr = self.addr
                            print("\nCLE ALLER:", self.aes_key_to, '\n')

                        elif "destination" in dest:
                            # On devient une extrémité
                            nb_keys = int(dest.split(',')[1])
                            EXTREMITY = True  # pour gérer le cas spécial où on est extrémité de la connexion
                            self.messageHandler = ExtremityHandler(self)
                            aes_node_key = message['m']
                            self.from_addr = self.addr
                            print("\nCLE DU NOEUD:", aes_node_key, '\n')

                        else:  # cas d'un noeud intermédiaire et de clef retour
                            aes_key_back = message['m']
                            self.to_addr = dest.split(',')[1].split(':') # ip:port
                            self.sock_to = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                self.sock_to.connect((self.to_addr[0], int(self.to_addr[1])))

                                relayHandler = RelayHandler(self)
                                relayHandler.start_reverse_relay()
                                self.messageHandler = relayHandler
                            except:
                                print("Can't contact the next node")
                            print("\nCLE RETOUR:", aes_key_back, '\n')

                    # EXTREMITY
                    elif not isSetUp and frame["action"] == "key_establishment":
                        message = pickle.loads(decrypt(raw_message, aes_node_key))
                        receiving_keys.append(message['m'])

                        if len(receiving_keys) == nb_keys:
                            isSetUp = True

                            print('\n', receiving_keys)
                            print("je suis une extrémité de la connexion (mais je ne suis pas implémenté pour le moment)\n")
                            print("maintenant il faut continuer le programme monsieur svp")

                    # Après l'établissement

                    else:
                        self.messageHandler.handle_message(raw_message)

                    self.sock_from.send(b"ACK")

            except socket.error as e:
                print(e)
                print(f"An error occured in the connection from {self.addr}")
                break


class NodeServer:
    def __init__(self, port):
        self.port = port

        self.key = PrivateKey()
        # self.privkey = "0x" + self.key.serialize()  # hexa
        # self.pubkey = self.key.pubkey.serialize()   # pas hexa
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
            requests.get(ANNOUNCE_URL + f"/relays/add-myself/{self.port}/{base64.b64encode(self.pubkey).decode()}")
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
                print("Socket is dead :", e)
                break
