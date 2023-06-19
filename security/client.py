import random

import requests

from config import ANNOUNCE_URL
from connection import ConnectionClient, NodeObject
from utils import *


class HiddenServiceClient:

    def __init__(self, serviceHash: str):
        self.serviceHash = serviceHash

        self.availableRelays: list = None
        self.rdvCircuit = None
        self.introducerCircuit = None

    def _getUnusedRelay(self):
        elem = self.availableRelays.pop()
        return elem[0].replace('_', '/'), elem[1], elem[2]

    def connect(self):

        ### Getting relays/services info from public server ###

        self.availableRelays = list(set(map(lambda x: tuple(x), requests.get(ANNOUNCE_URL + f"/relays").json())))
        random.shuffle(self.availableRelays)
        # format : (key,ip,port)

        services = requests.get(ANNOUNCE_URL + f"/services").json()
        random.shuffle(services)

        ### Building a circuit to a Rendez-vous relay ###

        rdvNode = NodeObject(*self._getUnusedRelay())
        L = []
        for i in range(3):
            L.append(NodeObject(*self._getUnusedRelay()))
        print("Etablissement de la connexion avec le point de rendez-vous:")
        self.rdvCircuit = ConnectionClient(rdvNode, L)


        ### Building a circuit to an introducer to the hidden service ###

        for (hash, key, ip, port) in services:
            if hash == self.serviceHash:
                self.introducerMetadata = (hash, key.replace('_', '/'), ip, port)
                break
        else:
            raise RuntimeError("Hidden service not found in services list.")

        L = []
        for i in range(3):
            L.append(NodeObject(*self._getUnusedRelay()))
        print("Etablissement de la connexion avec le point d'intro:")
        self.introducerCircuit = ConnectionClient(NodeObject(*self.introducerMetadata[1:]), L)


    def send(self, message:str):
        ### Passing Rendez-vous relay and one time password through the introducer to the hidden service ###

        raw_message = {'service': self.serviceHash, 'message': message }
        build_send_message(self.introducerCircuit.s, "INTRO_CLIENT_SIDE", "AES", self.introducerCircuit.priv_node_key,
                           None, raw_message, self.introducerCircuit.sending_keys, len(self.introducerCircuit.interm))

        print(f'''Envoyé "{raw_message['message']}" à {raw_message['service']}''')

        # we now have a ConnectionClient object wired to the hidden service

        ### Ping the hidden service ###


    def close(self):

        self.rdvCircuit.close()
        self.introducerCircuit.close()
