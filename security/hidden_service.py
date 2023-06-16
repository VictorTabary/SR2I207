import requests
import time
import random
from threading import Thread
from secp256k1 import PrivateKey

from security.config import ANNOUNCE_URL, ANNOUNCE_DELAY
from security.connection import ConnectionClient, NodeObject
from security.utils import *


class HiddenService:
    def __init__(self):
        self.key = PrivateKey()
        self.privkey = "0x" + self.key.serialize()  # hexa
        self.pubkey = self.key.pubkey.serialize()   # pas hexa
        #self.hash = service_name(self.pubkey)
        self.hash = "empty"

        self.port = 10000

        self.introCircuits = []

    def _getUnusedRelay(self):
        elem = self.availableRelays.pop()
        return elem[0].replace('_', '/'), elem[1], elem[2]
    
    def announce_to_relay(self):
        while True:
            for intro in self.introducerNodes:
                requests.get(ANNOUNCE_URL + f"/services/add/{self.hash}/{intro.key.replace('/', '_')}/{intro.ip}/{intro.port}/")
            time.sleep(ANNOUNCE_DELAY)

    def start(self):
        self.availableRelays = list(set(map(lambda x: tuple(x), requests.get(ANNOUNCE_URL + f"/relays").json())))
        random.shuffle(self.availableRelays)

        self.introducerNodes = []
        for i in range(3):
            self.introducerNodes.append(NodeObject(*self._getUnusedRelay()))

        Thread(target=self.announce_to_relay).start()

        # se connecter aux noeuds d'intro
        print("Etablissement de la connexion avec les points d'intros")
        for node in self.introducerNodes:
            L = []
            for i in range(3):
                L.append(NodeObject(*self._getUnusedRelay()))
            circuit = ConnectionClient(node, L)
            self.introCircuits.append(circuit)

            raw_message = self.hash
            build_send_message(circuit.s, "INTRO_SERVER_SIDE", "AES", circuit.priv_node_key, None, raw_message, circuit.sending_keys, len(circuit.interm))

        print("Pour debuguer: \nles noeuds suivant sont toujours dispos:", self.availableRelays)

