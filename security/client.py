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

    def send_intro(self, action, message):
        raw_message = {'service': self.serviceHash, 'message': message }
        build_send_message(self.introducerCircuit.s, action, "AES", self.introducerCircuit.priv_node_key,
                           None, raw_message, self.introducerCircuit.sending_keys, len(self.introducerCircuit.interm))

        #print(f'''Envoyé "{raw_message['message']}" à {raw_message['service']}''')

    
    def send_rdv(self, action, message):
        raw_message = {'conn_id': self.conn_id, 'message': message }
        build_send_message(self.rdvCircuit.s, action, "AES", self.rdvCircuit.priv_node_key,
                           None, raw_message, self.rdvCircuit.sending_keys, len(self.rdvCircuit.interm))

        #print(f'''Envoyé "{raw_message['message']}" sur la connexion {raw_message['conn_id']}''')


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

        action = "RDV_GET_CONN_ID"
        raw_message = None
        build_send_message(self.rdvCircuit.s, action, "AES", self.rdvCircuit.priv_node_key,
                           None, raw_message, self.rdvCircuit.sending_keys, len(self.rdvCircuit.interm))
        raw_id = listen(self.rdvCircuit.s)
        self.conn_id = pickle.loads(decrypt(raw_id, self.rdvCircuit.priv_node_key))['message']


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

        self.send_intro("INTRO_GET_KEY", "")
        raw_key = listen(self.introducerCircuit.s)
        key = '0x' + base64.b64decode(pickle.loads(decrypt(raw_key, self.introducerCircuit.priv_node_key))['message']).hex()


        ### Generate one-time password and send it to RDV
        self.otp = get_otp()
        message = self.otp
        self.send_rdv("RDV_CLIENT_OTP", message)

         
        ### Passing Rendez-vous relay, connection id and one time password through the introducer to the hidden service ###
        node_addr = self.rdvNode.ip + ':' + str(self.rdvNode.port)
        raw_message = {'rdv': node_addr, 'key': self.rdvNode.key, 'conn_id': self.conn_id, 'otp': self.otp}
        message = ecies.encrypt(key, pickle.dumps(raw_message))
        self.send_intro("INTRO_CLIENT_SIDE", message)


        # envoyer raw_message['otp'] au point de rendez-vous et implémenter la réception




        # we now have a ConnectionClient object wired to the hidden service

        ### Ping the hidden service ###    

