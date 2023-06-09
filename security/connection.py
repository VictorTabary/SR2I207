from Crypto.PublicKey import ECC
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import secrets
import string
import socket


PASSWORD_SIZE = 15
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
 
def get_private_key():
    salt = b"this is a random salt"
    password = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(PASSWORD_SIZE))
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key
 
def encrypt(raw, private_key):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))
 
def decrypt(enc, private_key):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


def send_message(host, port, message):
    print(message)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(message + b'\n')
        s.close()
    except:
        print("host down")


class Node:
    def __init__(self, ip, key):
        self.ip = ip
        self.key = key
    
    def __str__(self):
        return f"Node at address {self.__ip} with public key \n{self.__key}."
    

class Connection:
    def __init__(self, dest: Node, interm: list[Node]):
        self.dest = dest
        self.interm = interm

        self.sending_keys = []
        self.receiving_keys = []

        self.conn = self.establish_conn()

    def establish_conn(self):
        for i in range(len(self.interm)):
            self.Pi = self.interm[i].key
            # choisir la clé AES256 et l'enregistrer
            self.priv_aes_key = get_private_key()
            self.sending_keys.append(self.priv_aes_key)

            # la chiffrer avec la clé publique ECDSA et l'encapsuler pour l'envoyer
            self.enc_key = base64.b64encode(b"private key from ecdsa")                  # NOT DONE YET
            for j in range(i)[::-1]:
                self.enc_key = encrypt(self.enc_key, self.sending_keys[j])

            # l'envoyer au destinataire
            send_message(self.interm[i].ip, 9050, base64.b64encode(self.enc_key))

            # faire pareil avec les clés de déchiffrement au retour
        
        # faire pareil avec la clé du noeud destinataire
        self.priv_node_key = get_private_key()


        # envoyer tous les clefs du retour au destinataire

        print(self.sending_keys)
    

    def send(self, message):
        """Une fois que la connexion est établie, pour envoyer un message"""
        self.enc_mess = encrypt(message, self.priv_node_key)
        for i in range(len(self.interm))[::-1]:
            self.enc_mess = encrypt(self.enc_mess, self.sending_keys[i])
        send_message(self.dest.ip, 9050, base64.b64encode(self.enc_key))


con = Connection(Node("localhost", "b"), [Node("localhost", "b")])