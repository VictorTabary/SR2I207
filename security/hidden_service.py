import requests
import time
import random
from threading import Thread
from secp256k1 import PrivateKey

from config import ANNOUNCE_URL, ANNOUNCE_DELAY
from connection import ConnectionClient, NodeObject
from utils import *


def get_available_relays():
    L = list(set(map(lambda x: tuple(x), requests.get(ANNOUNCE_URL + f"/relays").json())))
    print(f"available relays : {len(L)}")
    return L

class HiddenService:
    def __init__(self):
        self.key = PrivateKey()
        self.privkey = "0x" + self.key.serialize()  # hexa
        self.pubkey = self.key.pubkey.serialize()   # pas hexa
        #self.hash = service_name(self.pubkey)
        self.hash = "abcdefghijklmnopqrstuvwxyz"

        self.port = 10000   # à quoi ça sert?

        self.introCircuits = []

    def _getUnusedRelay(self):
        # S'il y a une exception ici, assez probablement il n'y avait pas assez de relais dans la liste.
        elem = self.availableRelays.pop()
        return elem[0].replace('_', '/'), elem[1], elem[2]
    
    def announce_to_relay(self):
        while True:
            for intro in self.introducerNodes:
                requests.get(ANNOUNCE_URL + f"/services/add/{self.hash}/{intro.key.replace('/', '_')}/{intro.ip}/{intro.port}/")
            time.sleep(ANNOUNCE_DELAY)


    def send_rdv(self, circuit, conn_id, action, message):
        raw_message = {'conn_id': conn_id, 'message': message}
        build_send_message(circuit.s, action, "AES", circuit.priv_node_key,
                           None, raw_message, circuit.sending_keys, len(circuit.interm))

        #print(f'''Envoyé "{raw_message['message']}" sur la connexion {raw_message['conn_id']}''')


    def send_client(self, circuit, conn_id, info, message, key):
        to_relay = {'info': info, 'message': message}
        ciphered = encrypt(pickle.dumps(to_relay), key)
        raw_message = {'conn_id': conn_id, 'message': ciphered}
        build_send_message(circuit.s, "TRANSFER_CLIENT", "AES", circuit.priv_node_key,
                           None, raw_message, circuit.sending_keys, len(circuit.interm))


    def listenRdvRequest(self, circuit, conn_id, otp):
        self.send_rdv(circuit, conn_id, "RDV_SERVICE_OTP", otp)
        # wait for the message saying that the connection is up
        data = listen(circuit.s)
        message = pickle.loads(decrypt(data, circuit.priv_node_key))['message']
        while message != "CONNECTION_UP":
            data = listen(circuit.s)
            message = pickle.loads(decrypt(data, circuit.priv_node_key))['message']

        exchangeKey = None
        while True:
            data = listen(circuit.s)
            if data:
                frame = pickle.loads(decrypt(data, circuit.priv_node_key))
                if frame['action'] == "KEY_SETUP": 
                    # cas spécial pour le départ
                    exchangeKey = ecies.decrypt(self.privkey, frame['message'])
                    self.send_rdv(circuit, conn_id, "ACK", encrypt("Key received".encode(), exchangeKey))
                    print("\nConnection with the client is now up !")
                else:
                    message = pickle.loads(decrypt(frame['message'], exchangeKey))
                    if message['info'] == "PING":
                        self.send_client(circuit, conn_id, "PONG", message['message'], exchangeKey)


    def listenIntroRequests(self, circuit):
        while True:
            data = listen(circuit.s)
            # gérer les connexions ici
            if data:
                frame = pickle.loads(decrypt(data, circuit.priv_node_key))
                message = pickle.loads(ecies.decrypt(self.privkey, frame['message']))
                print("Reçu : ",message) # debug ; TODO : delete

                rdv = message['rdv'].split(':')
                rdvNode = NodeObject(message['key'], rdv[0], int(rdv[1]))
                conn_id = message['conn_id']
                otp = message['otp']

                print("Etablissement de la connexion avec le point de rendez-vous")
                L = []
                for i in range(3):
                    L.append(NodeObject(*self._getUnusedRelay()))
                rdvCircuit = ConnectionClient(rdvNode, L)

                Thread(target=self.listenRdvRequest, args=(rdvCircuit, conn_id, otp)).start()



    def start(self):
        print("Hidden Service")
        self.availableRelays = get_available_relays()
        random.shuffle(self.availableRelays)

        self.introducerNodes = []
        for i in range(3):
            self.introducerNodes.append(NodeObject(*self._getUnusedRelay()))

        Thread(target=self.announce_to_relay).start()

        # se connecter aux noeuds d'intro
        print("Etablissement de la connexion avec les points d'intro")
        for node in self.introducerNodes:
            L = []
            for i in range(3):
                L.append(NodeObject(*self._getUnusedRelay()))
            circuit = ConnectionClient(node, L)
            self.introCircuits.append(circuit)

            raw_message = self.hash + ',' + base64.b64encode(self.pubkey).decode()
            build_send_message(circuit.s, "INTRO_SERVER_SIDE", "AES", circuit.priv_node_key, None, raw_message, circuit.sending_keys, len(circuit.interm))

        #print("Pour debuguer: \nles noeuds suivant sont toujours dispos:", self.availableRelays)

        # écouter les connexions entrantes
        for circ in self.introCircuits:
            Thread(target=self.listenIntroRequests, args=(circ, )).start()



