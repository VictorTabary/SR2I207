import random

import requests
import pickle

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

    def close(self):

        self.rdvCircuit.close()
        self.introducerCircuit.close()

    def send(self, action, message):
        raw_message = {'service': self.serviceHash, 'message': message }
        build_send_message(self.introducerCircuit.s, action, "AES", self.introducerCircuit.priv_node_key,
                           None, raw_message, self.introducerCircuit.sending_keys, len(self.introducerCircuit.interm))

        print(f'''Envoyé "{raw_message['message']}" à {raw_message['service']}''')


    def connect(self):
        ### Getting relays/services info from public server ###

        self.availableRelays = list(set(map(lambda x: tuple(x), requests.get(ANNOUNCE_URL + f"/relays").json())))
        random.shuffle(self.availableRelays)
        # format : (key,ip,port)

        services = requests.get(ANNOUNCE_URL + f"/services").json()
        random.shuffle(services)

        ### Building a circuit to a Rendez-vous relay ###

        self.rdvNode = NodeObject(*self._getUnusedRelay())
        L = []
        for i in range(3):
            L.append(NodeObject(*self._getUnusedRelay()))
        print("Etablissement de la connexion avec le point de rendez-vous:")
        self.rdvCircuit = ConnectionClient(self.rdvNode, L)


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


        self.send("INTRO_GET_KEY", "fqfqzfz")
        raw_key = listen(self.introducerCircuit.s)
        key = base64.b64decode(pickle.loads(decrypt(raw_key, self.introducerCircuit.priv_node_key))['message'])
        print(key)

        
        ### Passing Rendez-vous relay and one time password through the introducer to the hidden service ###
        node_addr = self.rdvNode.ip + ':' + str(self.rdvNode.port)
        otp = get_otp()
        message = {'rdv': node_addr, 'otp': otp}
        # TODO: chiffrer le message avant de l'envoyer
        #   pour ça il faut que le hidden service envoie sa clef publique aux points d'intro à la connexion
        #   et après il faut gérer les connexions au hiddens service
        self.send("INTRO_CLIENT_SIDE", message)



        # we now have a ConnectionClient object wired to the hidden service

        ### Ping the hidden service ###    

