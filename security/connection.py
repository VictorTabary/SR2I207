import socket

from utils import *


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
            # choisir les clés AES256 et les enregistrer
            priv_aes_key_aller, priv_aes_key_retour = get_private_key(), get_private_key()
            self.sending_keys.append(priv_aes_key_aller)
            self.receiving_keys.append(priv_aes_key_retour)
            info = ['aller', 'retour,']
            if i < len(self.interm)-1:
                info[1] += self.interm[i+1].ip + ":" + str(self.interm[i+1].port)
            else:
                info[1] += self.dest.ip + ":" + str(self.dest.port)
            build_send_message(self.s, "key_establishment", "ECIES", self.Pi, info, pickle.dumps([priv_aes_key_aller, priv_aes_key_retour]), self.sending_keys, i)
        
        # faire pareil avec la clé du noeud destinataire
        self.priv_node_key = get_private_key()
        next = ["destination", str(len(self.interm))]
        build_send_message(self.s, "key_establishment", "ECIES", self.dest.key, next, self.priv_node_key, self.sending_keys, len(self.interm))

        # envoyer toutes les clefs du retour au destinataire
        info = ["clefs_retour"]
        build_send_message(self.s, "key_establishment", "AES", self.priv_node_key, info, pickle.dumps(self.receiving_keys), self.sending_keys, len(self.interm))
        

        # for debug purposes
        print(self.sending_keys)
        print(self.receiving_keys)
        print(self.priv_node_key)

        self.s.close()
