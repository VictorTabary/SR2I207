from config import ANNOUNCE_URL
from connection import ConnectionClient, NodeObject

import requests
import random


class HiddenServiceClient:

    def __init__(self, serviceHash: str):
        self.serviceHash = serviceHash

        self.availableRelays = None
        self.introducerMetadata = None

    def connect(self):
        self.availableRelays = set(requests.get(ANNOUNCE_URL + f"/relays").json())
        print(self.availableRelays)

        services = requests.get(ANNOUNCE_URL + f"/services").json()
        random.shuffle(services)

        for (hash, key, ip) in services:
            if hash == self.serviceHash:
                self.introducerMetadata = (hash, key, ip)
                break
        else:
            raise RuntimeError("Hidden service not found in services list.")

        # hash,key,ip

        # obtenir un point d'intro pour le service
        # obtenir les relais
        # choisir un point de rdv
        # établir connexion au point de rdv
        # établir un circuit jusqu'au point d'intro
        # donner le pt de rdv & le one time password au travers du point d'intro
        # (établissement)
        # ping au hidden service

        pass


h = HiddenServiceClient("empty")
h.connect()
