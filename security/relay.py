import socket
import time
from enum import Enum
from threading import Thread

import ecies
import requests
from secp256k1 import PrivateKey

from security.config import F_PACKET_SIZE, ANNOUNCE_DELAY, ANNOUNCE_URL, RELAY_LISTENING_IP
from security.utils import *



class ExtremityRole(Enum):
    Undefined = 0
    RendezVous = 1
    IntroductionPoint = 2


class ExtremityHandler:
    def __init__(self, circuit):
        self.circuit = circuit
        self.role = ExtremityRole.Undefined
    def handle_message(self, raw_message):

        """
        if ping:
            répondre au ping, peu importe le rôle.
            return
        """

        match self.role:
            case ExtremityRole.Undefined:
                pass
            case ExtremityRole.RendezVous:
                pass
            case ExtremityRole.IntroductionPoint:
                pass

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
        self.sock_to: socket.socket = None # utilisé uniquement si on n'est pas une extrémité

    def close(self):
        self.stop_threads = True
        pass  # todo
        """
        for s in self.socks:
            s.shutdown(socket.SHUT_RDWR); s.close()
            """
        
    def listen(self, conn):
        # écouter tant qu'on n'a pas 4 octets
        data = b''
        while len(data) != F_PACKET_SIZE:
            data += conn.recv(F_PACKET_SIZE - len(data))
        packet_size = int.from_bytes(data, 'big')

        packet = b''
        while len(packet) != packet_size:
            packet += conn.recv(packet_size - len(packet))
        return packet

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
                data = self.listen(self.sock_from)
                if data:
                    frame = pickle.loads(data)
                    print(frame)

                    raw_message = frame["enc_message"]
                    if not EXTREMITY and frame["action"] == "key_establishment":
                        message = pickle.loads(ecies.decrypt(self.server.privkey, raw_message))

                        dest = message['info']
                        if dest[0] == 'aller':  # cas d'un noeud intermédiaire
                            # clef aller
                            keys = pickle.loads(message['m'])

                            self.aes_key_to = keys[0]
                            self.from_addr = self.addr
                            print("\nCLE ALLER:", self.aes_key_to)

                            # clef retour
                            aes_key_back = keys[1]
                            self.to_addr = dest[1].split(',')[1].split(':') # ip:port
                            self.sock_to = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                self.sock_to.connect((self.to_addr[0], int(self.to_addr[1])))

                                relayHandler = RelayHandler(self)
                                relayHandler.start_reverse_relay()
                                self.messageHandler = relayHandler
                            except:
                                print("Can't contact the next node")
                            print("\nCLE RETOUR:", aes_key_back, '\n')

                        elif dest[0] == "destination":
                            # On devient une extrémité
                            nb_keys = int(dest[1])
                            EXTREMITY = True  # pour gérer le cas spécial où on est extrémité de la connexion
                            self.messageHandler = ExtremityHandler(self)
                            aes_node_key = message['m']
                            self.from_addr = self.addr
                            print("\nCLE DU NOEUD:", aes_node_key, '\n')

                    # EXTREMITY
                    elif not isSetUp and frame["action"] == "key_establishment":
                        message = pickle.loads(decrypt(raw_message, aes_node_key))
                        receiving_keys = pickle.loads(message['m'])

                        assert len(receiving_keys) == nb_keys
                        isSetUp = True

                        print('\n', receiving_keys)
                        print("je suis une extrémité de la connexion (mais je ne suis pas implémenté pour le moment)\n")
                        print("maintenant il faut continuer le programme monsieur svp")

                    # Après l'établissement
                    else:
                        self.messageHandler.handle_message(raw_message)

            except socket.error as e:
                print(e)
                print(f"An error occured in the connection from {self.addr}")
                break


class NodeServer:
    def __init__(self, port):
        self.s = None
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
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((RELAY_LISTENING_IP, self.port))
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
