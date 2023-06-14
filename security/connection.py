import base64
import socket
import ecies
import pickle
from security.utils import *
from threading import Thread
from secp256k1 import PrivateKey
import time
import requests

ANNOUNCE_DELAY = 1*60 # seconds
ANNOUNCE_URL = "http://localhost:8080"


class CircuitNode:
    
    def __init__(self, conn, addr, server):
        self.conn = conn
        self.addr = addr
        self.server = server
        self.stop_threads = False

    def close(self):
        self.stop_threads = True
        pass # todo
        """
        for s in self.socks:
            s.shutdown(socket.SHUT_RDWR); s.close()
            """

    def handle_request(self):
        print('Connected by', self.addr)

        aes_key_to, aes_key_back = b'', b''
        aes_node_key = b''
        from_addr, to_addr = {}, {}
        sock = ''

        # utilisés seulement si extrémité
        EXTREMITY = False
        receiving_keys = []
        nb_keys = 0
        SET_UP = False

        while True and self.stop_threads == False:
            try:
                data = self.conn.recv(2048)
                if data:
                    frame = pickle.loads(data)
                    print(frame)
                    if frame["action"] == "key_establishment" and not EXTREMITY:
                        message = pickle.loads(ecies.decrypt(self.server.privkey, frame["enc_message"]))
                        #print(message)
                        dest = message['info']                      
                        if dest == 'aller':  # cas d'un noeud intermédiaire et de clef aller
                            aes_key_to = message['m']
                            from_addr = self.addr
                            print("\nCLE ALLER:", aes_key_to, '\n')

                        elif "destination" in dest:
                            nb_keys = int(dest.split(',')[1])
                            EXTREMITY = True    # pour gérer le cas spécial où on est extrémité de la connexion
                            aes_node_key = message['m']
                            from_addr = self.addr
                            print("\nCLE DU NOEUD:", aes_node_key, '\n')
                        
                        else: # cas d'un noeud intermédiaire et de clef retour
                            aes_key_back = message['m']
                            to_addr = dest.split(',')[1].split(':')
                            sock_to = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                sock_to.connect((to_addr[0], int(to_addr[1])))
                            except:
                                print("Can't contact the next node")
                            print("\nCLE RETOUR:", aes_key_back, '\n')
                    
                    elif EXTREMITY and not SET_UP and frame["action"] == "key_establishment":
                        message = pickle.loads(decrypt(frame["enc_message"], aes_node_key))
                        receiving_keys.append(message['m'])

                        if len(receiving_keys) == nb_keys:
                            SET_UP = True

                            #send_message(sock_back, b"hello")
                            print('\n', receiving_keys)

                            print("je suis une extrémité de la connexion (mais je ne suis pas implémenté pour le moment)\n")
                            print("maintenant il faut continuer le programme monsieur svp")
                    
                    # pour le relai
                    elif frame["action"] == "relay":
                        decr_message = decrypt(frame["enc_message"], aes_key_to)
                        send_message(sock_to, decr_message)

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




class NodeObject:
    def __init__(self, ip, port, key):
        self.ip = ip
        self.port = port
        self.key = key
    
    def __str__(self):
        return f"Node at address {self.ip} on port{self.port} with public key \n{self.key}."



class ConnectionClient:
    def __init__(self, dest: NodeObject, interm: list[NodeObject]):
        self.dest = dest
        self.interm = interm

        self.sending_keys = []
        self.receiving_keys = []

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.interm[0].ip, self.interm[0].port))
        except:
            print('Host seems down')

        self.conn = self.establish_conn()


    def establish_conn(self):
        for i in range(len(self.interm)):
            self.Pi = self.interm[i].key
            # choisir la clé AES256 et l'enregistrer
            self.priv_aes_key = get_private_key()
            self.sending_keys.append(self.priv_aes_key)
            next = "aller"
            build_send_message(self.s, "key_establishment", "ECIES", self.Pi, next, self.priv_aes_key, self.sending_keys, i)

            # faire pareil avec les clés de déchiffrement au retour            
            self.priv_aes_key = get_private_key()
            self.receiving_keys.append(self.priv_aes_key)
            next = "retour,"
            if i < len(self.interm)-1:
                next += self.interm[i+1].ip + ":" + str(self.interm[i+1].port)
            else:
                next += self.dest.ip + ":" + str(self.dest.port)
            build_send_message(self.s, "key_establishment", "ECIES", self.Pi, next, self.priv_aes_key, self.sending_keys, i)
        
        # faire pareil avec la clé du noeud destinataire
        self.priv_node_key = get_private_key()
        next = "destination,"+str(len(self.interm))
        build_send_message(self.s, "key_establishment", "ECIES", self.dest.key, next, self.priv_node_key, self.sending_keys, len(self.interm))

        # envoyer toutes les clefs du retour au destinataire
        for i in range(len(self.receiving_keys)):
            next = "clefs_retour"
            build_send_message(self.s, "key_establishment", "AES", self.priv_node_key, next, self.receiving_keys[i], self.sending_keys, len(self.interm))
        

        # for debug purposes
        print(self.sending_keys)
        print(self.receiving_keys)
        print(self.priv_node_key)

        self.s.close()
