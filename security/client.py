from security.connection import ConnectionClient, NodeObject


class HiddenServiceClient:

    def __init__(self, service: str):
        pass

    def connect(self):
        # obtenir un point d'intro pour le service
        # obtenir les relais
        # choisir un point de rdv
        # établir connexion au point de rdv
        # établir un circuit jusqu'au point d'intro
        # donner le pt de rdv & le one time password au travers du point d'intro
        # (établissement)
        # ping au hidden service

        pass


conn = ConnectionClient(
    NodeObject("localhost", 9054, b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS'),
    [NodeObject("localhost", 9050, b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS'),
     NodeObject("localhost", 9052, b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS')])