import random

import requests

from config import ANNOUNCE_URL
from connection import ConnectionClient, NodeObject


class HiddenServiceClient:

    def __init__(self, serviceHash: str):
        self.serviceHash = serviceHash

        self.availableRelays: list = None
        self.introducerCircuit = None

    def _getUnusedRelay(self):
        return self.availableRelays.pop()

    def connect(self):

        ### Getting relays/services info from public server ###

        self.availableRelays = list(set(requests.get(ANNOUNCE_URL + f"/relays").json()))
        random.shuffle(self.availableRelays)
        # format : (key,ip,port)

        services = requests.get(ANNOUNCE_URL + f"/services").json()
        random.shuffle(services)

        ### Building a circuit to a Rendez-vous relay ###

        # TODO

        ### Building a circuit to an introducer to the hidden service ###

        for (hash, key, ip, port) in services:
            if hash == self.serviceHash:
                self.introducerMetadata = (hash, key, ip, port)
                break
        else:
            raise RuntimeError("Hidden service not found in services list.")

        L = []
        for i in range(3):
            L.append(NodeObject(*self._getUnusedRelay()))
        self.introducerCircuit = ConnectionClient(NodeObject(*self.introducerMetadata[1:]), L)

        ### Passing Rendez-vous relay and one time password through the introducer to the hidden service ###

        # TODO

        # we now have a ConnectionClient object wired to the hidden service

        ### Ping the hidden service ###

        # TODO

        return True


h = HiddenServiceClient("empty")
h.connect()
