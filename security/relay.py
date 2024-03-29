import socket
import time
from enum import Enum
from threading import Thread


import ecies
import requests
from secp256k1 import PrivateKey

from config import F_PACKET_SIZE, ANNOUNCE_DELAY, ANNOUNCE_URL, RELAY_LISTENING_IP
from utils import *


class ExtremityRole(Enum):
    Undefined = 0
    RendezVous = 1
    IntroductionPoint = 2


class RelayHandler:
    def __init__(self, circuit):
        self.circuit = circuit
        self.thread = None

    def handle_message(self, raw_message):
        # elif frame["action"] == "relay":
        send_message(self.circuit.sock_to, raw_message['message'])

    def start_reverse_relay(self):
        def handle_reverse():
            while True:
                raw_data = listen(self.circuit.sock_to)
                decr_frame = pickle.loads(decrypt(raw_data, self.circuit.aes_key_back))

                # print("CONNEXION RECUE DANS L'AUTRE SENS:", decr_frame)

                send_message(self.circuit.sock_from, decr_frame['message'])

        self.thread = Thread(target=handle_reverse)
        self.thread.start()


class ExtremityHandler:
    def __init__(self, circuit):
        self.circuit = circuit
        self.role = ExtremityRole.Undefined

        # quand on est intro
        self.serviceName = None
        self.serviceKey = None

        # quand on est rdv
        self.conn_id = None

    def pong(self, raw_message):
        # print("RECEIVED PING, SENDING PONG")
        build_send_message(self.circuit.sock_from, "PING", "AES", self.circuit.aes_node_key, self.circuit.from_addr,
                           raw_message, self.circuit.receiving_keys[::-1], self.circuit.nb_keys)

    def handle_message(self, frame):
        if frame['action'] == 'PING':
            self.pong(frame['message'])         


        elif frame['action'] == 'INTRO_SERVER_SIDE':
            self.role = ExtremityRole.IntroductionPoint
            self.serviceName = frame['message'].split(',')[0]
            self.serviceKey = frame['message'].split(',')[1].encode()


        elif frame['action'] == 'RDV_GET_CONN_ID':
            self.role = ExtremityRole.RendezVous


        elif frame['action'] == 'RDV_CLIENT_OTP':
            id = frame['message']['conn_id']
            if id != self.conn_id or self.circuit.server.rdvConns[self.conn_id]['client'] != None:
                raw_message = f"Connection {frame['message']['conn_id']} not found"
                build_send_message(self.circuit.sock_from, "ERROR", "AES", self.circuit.aes_node_key,
                                   self.circuit.from_addr, raw_message, self.circuit.receiving_keys[::-1],
                                   self.circuit.nb_keys)
            else:
                client_otp = frame['message']['message']
                self.circuit.server.rdvConns[self.conn_id]['client'] = [self.circuit, client_otp]


        elif frame['action'] == 'INTRO_GET_KEY':
            self.serviceName = frame['message']['service']
            if self.serviceName not in self.circuit.server.introducedServices.keys():
                raw_message = f"Service {self.serviceName} not found"
                build_send_message(self.circuit.sock_from, "ERROR", "AES", self.circuit.aes_node_key,
                                   self.circuit.from_addr, raw_message, self.circuit.receiving_keys[::-1],
                                   self.circuit.nb_keys)
            else:
                raw_message = self.circuit.server.introducedServices[self.serviceName]["key"]
                build_send_message(self.circuit.sock_from, "KEY", "AES", self.circuit.aes_node_key, self.circuit.from_addr,
                           raw_message, self.circuit.receiving_keys[::-1], self.circuit.nb_keys)


        elif frame['action'] == 'INTRO_CLIENT_SIDE':
            # vérifier que le noeud est bien point d'intro pour le service demandé, sinon refuser
            self.serviceName = frame['message']['service']
            if self.serviceName not in self.circuit.server.introducedServices.keys():
                raw_message = f"Service {self.serviceName} not found"
                build_send_message(self.circuit.sock_from, "ERROR", "AES", self.circuit.aes_node_key,
                                   self.circuit.from_addr, raw_message, self.circuit.receiving_keys[::-1],
                                   self.circuit.nb_keys)
            else:
                # si service bien là, relayer les infos au service
                transfer = self.circuit.server.introducedServices[self.serviceName]["func"]
                transfer(frame['message']['message'])

                # il faudrait gérer le retour avec la fonction transfer aussi
                # donc la déclarer un peu autrement pour transférer aussi au retour


        elif frame['action'] == "RDV_SERVICE_OTP":
            id = frame['message']['conn_id']
            if id not in self.circuit.server.rdvConns.keys() or (id in self.circuit.server.rdvConns.keys() and self.circuit.server.rdvConns[id]['service'] != None):
                raw_message = f"Connection {frame['message']['conn_id']} not found"
                build_send_message(self.circuit.sock_from, "ERROR", "AES", self.circuit.aes_node_key,
                                   self.circuit.from_addr, raw_message, self.circuit.receiving_keys[::-1],
                                   self.circuit.nb_keys)
            elif self.circuit.server.rdvConns[id]['client'] == None:
                # dans ce cas c'est le bordel
                print(f"\n\n\nSERVICE OTP: bordel\t{self.circuit.server.rdvConns[id]}\n\n\n")
                pass
            else:
                service_otp = frame['message']['message']
                self.circuit.server.rdvConns[id]['service'] = [self.circuit, service_otp]

                if service_otp != self.circuit.server.rdvConns[id]['client'][1]:
                    raw_message = "Wrong OTP"
                    build_send_message(self.circuit.sock_from, "ERROR", "AES", self.circuit.aes_node_key,
                                   self.circuit.from_addr, raw_message, self.circuit.receiving_keys[::-1],
                                   self.circuit.nb_keys)
                else:
                    client_circuit = self.circuit.server.rdvConns[id]['client'][0]
                    raw_message = "CONNECTION_UP"

                    build_send_message(client_circuit.sock_from, "CONNECTION_STATE", "AES", client_circuit.aes_node_key,
                                    client_circuit.from_addr, raw_message, client_circuit.receiving_keys[::-1],
                                    client_circuit.nb_keys)

                    build_send_message(self.circuit.sock_from, "CONNECTION_STATE", "AES", self.circuit.aes_node_key,
                                    self.circuit.from_addr, raw_message, self.circuit.receiving_keys[::-1],
                                    self.circuit.nb_keys)
                    
                    self.circuit.server.rdvConns[id]['state'] = 'up'
        

        elif frame['action'] == "KEY_SETUP":
            id = frame['message']['conn_id']
            raw_message = frame['message']['message']
            service_circuit = self.circuit.server.rdvConns[id]['service'][0]

            build_send_message(service_circuit.sock_from, "KEY_SETUP", "AES", service_circuit.aes_node_key,
                                    service_circuit.from_addr, raw_message, service_circuit.receiving_keys[::-1],
                                    service_circuit.nb_keys)
        

        elif frame['action'] == "ACK":
            id = frame['message']['conn_id']
            raw_message = frame['message']['message']
            client_circuit = self.circuit.server.rdvConns[id]['client'][0]
            build_send_message(client_circuit.sock_from, "ACK", "AES", client_circuit.aes_node_key,
                                    client_circuit.from_addr, raw_message, client_circuit.receiving_keys[::-1],
                                    client_circuit.nb_keys)
            

        elif frame['action'] == "TRANSFER_SERVICE":
            id = frame['message']['conn_id']
            raw_message = frame['message']['message']
            service_circuit = self.circuit.server.rdvConns[id]['service'][0]

            build_send_message(service_circuit.sock_from, frame['action'], "AES", service_circuit.aes_node_key,
                                    service_circuit.from_addr, raw_message, service_circuit.receiving_keys[::-1],
                                    service_circuit.nb_keys)
            

        elif frame['action'] == "TRANSFER_CLIENT":
            id = frame['message']['conn_id']
            raw_message = frame['message']['message']
            service_circuit = self.circuit.server.rdvConns[id]['service'][0]

            client_circuit = self.circuit.server.rdvConns[id]['client'][0]
            build_send_message(client_circuit.sock_from, "TRANSFER_CLIENT", "AES", client_circuit.aes_node_key,
                                    client_circuit.from_addr, raw_message, client_circuit.receiving_keys[::-1],
                                    client_circuit.nb_keys)
        


        match self.role:
            case ExtremityRole.Undefined:
                pass

            case ExtremityRole.RendezVous:
                if self.conn_id is None:
                    self.conn_id = get_id()
                    while self.conn_id in self.circuit.server.rdvConns.keys():
                        self.conn_id = get_id()
                    self.circuit.server.rdvConns[self.conn_id] = {'client': None, 'service': None, 'state': 'down'}

                    raw_message = self.conn_id
                    build_send_message(self.circuit.sock_from, "CONN_ID", "AES", self.circuit.aes_node_key,
                                   self.circuit.from_addr, raw_message, self.circuit.receiving_keys[::-1],
                                   self.circuit.nb_keys)                    
                    
            case ExtremityRole.IntroductionPoint:
                # stocker la fonction d'intro dans le serv
                relay_intro = lambda message: build_send_message(self.circuit.sock_from, "RELAY", "AES",
                                                                 self.circuit.aes_node_key, self.circuit.from_addr,
                                                                 message, self.circuit.receiving_keys[::-1],
                                                                 self.circuit.nb_keys)
                service_infos = {"func": relay_intro, "key": self.serviceKey}
                self.circuit.server.introducedServices[self.serviceName] = service_infos


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
        self.sock_to: socket.socket = None  # utilisé uniquement si on n'est pas une extrémité

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
        self.aes_node_key = None
        self.EXTREMITY = False
        self.nb_keys = 0
        self.isSetUp = False
        self.receiving_keys = []

        while True and self.stop_threads == False:
            try:
                data = listen(self.sock_from)
                if data:
                    if self.aes_key_to == None and self.aes_node_key == None:  # si le noeud n'a pas encore reçu sa clef AES
                        frame = pickle.loads(ecies.decrypt('0x' + self.server.privkey, data))
                    elif self.EXTREMITY:
                        frame = pickle.loads(decrypt(data, self.aes_node_key))
                    else:
                        frame = pickle.loads(decrypt(data, self.aes_key_to))

                    # print(frame)
                    if not self.EXTREMITY and frame["action"] == "key_establishment":
                        message = pickle.loads(frame['message'])

                        dest = message['info']
                        if dest[0] == 'aller':  # cas d'un noeud intermédiaire
                            # clef aller
                            keys = pickle.loads(message['m'])

                            self.aes_key_to = keys[0]
                            self.from_addr = self.addr
                            # print("\nCLE ALLER:", self.aes_key_to)

                            # clef retour
                            self.aes_key_back = keys[1]
                            self.to_addr = dest[1].split(',')[1].split(':')  # ip:port
                            self.sock_to = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                self.sock_to.connect((self.to_addr[0], int(self.to_addr[1])))

                                relayHandler = RelayHandler(self)
                                relayHandler.start_reverse_relay()
                                self.messageHandler = relayHandler
                            except:
                                # print("Can't contact the next node")
                                pass
                            # print("\nCLE RETOUR:", self.aes_key_back, '\n')

                        elif dest[0] == "destination":
                            # On devient une extrémité
                            self.nb_keys = int(dest[1])
                            self.EXTREMITY = True  # pour gérer le cas spécial où on est extrémité de la connexion
                            self.messageHandler = ExtremityHandler(self)
                            self.aes_node_key = message['m']
                            self.from_addr = self.addr
                            # print("\nCLE DU NOEUD:", self.aes_node_key, '\n')

                    # EXTREMITY
                    elif not self.isSetUp and frame["action"] == "key_establishment":
                        message = frame['message']
                        self.receiving_keys = pickle.loads(message)

                        assert len(self.receiving_keys) == self.nb_keys
                        self.isSetUp = True

                        # print('\n', self.receiving_keys)
                        # print("je suis une extrémité de la connexion (mais je ne suis pas implémenté pour le moment)\n")
                        # print("maintenant il faut continuer le programme monsieur svp")

                    # Relais
                    else:
                        self.messageHandler.handle_message(frame)

            except socket.error as e:
                print(e)
                print(f"An error occured in the connection from {self.addr}")
                break


class NodeServer:
    def __init__(self, port):
        self.s = None
        self.port = port

        self.key = PrivateKey()
        self.privkey = self.key.serialize()  # hexa
        self.pubkey = self.key.pubkey.serialize()  # pas hexa
        # self.privkey = base64.b64decode(b'AQcx++axCPTh3xOmYC8IzUSrrgynvVarDp+2fZj/wf4=').hex()
        # self.pubkey = base64.b64decode(b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS')

        self.circuits = []

        # pour les points d'intro
        self.introducedServices = dict()

        # pour les points de rdv
        self.rdvConns = dict()

    def __str__(self):
        return f"Node at address {self.ip} with public key \n{self.key}."

    def close(self):
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()
        for circuit in self.circuits:
            circuit.close()

    def announce_to_relay(self):
        while True:
            try:
                print("Announcing myself to public-relay-list")
                requests.get(
                    ANNOUNCE_URL + f"/relays/add-myself/{self.port}/{base64.b64encode(self.pubkey).decode().replace('/', '_')}")
                print("Announcing: Ok!")
            except Exception as e:
                print("Announcing: Failed! error:", e)

            time.sleep(ANNOUNCE_DELAY)

    def start(self):
        print(f"Listening on {RELAY_LISTENING_IP}:{self.port}")

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

