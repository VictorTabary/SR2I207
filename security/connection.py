import base64
import socket
import ecies
import pickle
from security.utils import *
from threading import Thread
from secp256k1 import PrivateKey



def send_message(host, port, message):
    print(host, port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(message + b'\n')
        s.close()
    except:
        print("Host down")



class NodeServer:
    def __init__(self, port):
        self.port = port

        self.key = PrivateKey()
        #self.privkey = "0x" + self.key.serialize()  # hexa
        #self.pubkey = self.key.pubkey.serialize()   # pas hexa
        self.privkey = base64.b64decode(b'AQcx++axCPTh3xOmYC8IzUSrrgynvVarDp+2fZj/wf4=').hex()
        self.pubkey = base64.b64decode(b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS')
    
    def __str__(self):
        return f"Node at address {self.ip} with public key \n{self.key}."
    
    def handle_request(self, conn, addr):
        print('Connected by', addr)
        while True:
            try:
                data = conn.recv(1024)
                if data:
                    frame = pickle.loads(data)
                    print(frame)
                    if frame["action"] == "key_establishment":
                        message = pickle.loads(ecies.decrypt(self.privkey, frame["enc_message"]))
                        print(message)                        
                        if message['dest'] == 'to':
                            aes_key_to = message['m']
                            from_addr = addr[0]
                            print("\nkey_establishment aller:", aes_key_to, '\nfrom address:', from_addr)
                        elif message['dest'] == "destination":
                            EXTREMITY = True    # pour gérer le cas spécial où on est extrémité de la connexion
                            print("je suis une extrémité de la connexion (mais je ne suis pas implémenté pour le moment)")
                        elif 'node' in message['dest']:   # il faut gérer le cas particulier des noeuds destinataires (ils reçoivent les clés de retour avec pour dest: node_{i})
                            print("je suis une extrémité de la connexion (mais je ne suis pas implémenté pour le moment)")
                        else:
                            aes_key_back = message['m']
                            to_addr = message['dest']
                            print("\nkey_establishment retour:", aes_key_back, '\nto address:', to_addr)
                    
                    # cas du relais à implémenter
                    # mettre des headers "relay_to" et "relay_from" pour savoir avec quelle clé déchiffrer le paquet

            except socket.error: 
                print(f"An error occured in the connection from {addr}")
                break
    
    def start(self):
        # penser à se déclarer dans la public-relay-list souvent (toutes les 2 minutes?)
        self.host = ''        # Symbolic name meaning all available interfaces   
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.host, self.port))
        self.s.listen()
        while True:
            conn, addr = self.s.accept()
            self.t = Thread(target=self.handle_request, args=(conn, addr))
            self.t.start()
            #self.t.run()



class NodeObject:
    def __init__(self, ip, port, key):
        self.ip = ip
        self.port = port
        self.key = key
    
    def __str__(self):
        return f"Node at address {self.ip} on port{self.port} with public key \n{self.key}."
    


class Connection:
    def __init__(self, dest: NodeObject, interm: list[NodeObject]):
        self.dest = dest
        self.interm = interm

        self.sending_keys = []
        self.receiving_keys = []

        self.conn = self.establish_conn()
    
    def encaps_message(self, addr, message):
        return pickle.dumps({'dest': addr, 'm': message})
    
    def encaps_frame(self, action, enc_message):
        return pickle.dumps({'action': action, 'enc_message': enc_message})

    def establish_conn(self):
        for i in range(len(self.interm)):
            self.Pi = self.interm[i].key
            # choisir la clé AES256 et l'enregistrer
            self.priv_aes_key = get_private_key()
            self.sending_keys.append(self.priv_aes_key)
            # la chiffrer avec la clé publique ECDSA et l'encapsuler pour l'envoyer
            self.clear_message = self.encaps_message('to', self.priv_aes_key)
            self.enc_key = ecies.encrypt('0x' + base64.b64decode(self.Pi).hex(), self.clear_message)
            self.frame = self.encaps_frame("key_establishment", self.enc_key)
            for j in range(i)[::-1]:
                next = {'ip': self.interm[j].ip, 'port': self.interm[j].port}
                self.clear_message = self.encaps_message(pickle.dumps(next), self.frame)
                self.enc_key = encrypt(self.clear_message, self.sending_keys[j])
                self.frame = self.encaps_frame("relay", self.enc_key)
            # l'envoyer au destinataire
            send_message(self.interm[0].ip, self.interm[0].port, self.frame)


            # faire pareil avec les clés de déchiffrement au retour            
            self.priv_aes_key = get_private_key()
            self.receiving_keys.append(self.priv_aes_key)
            if i < len(self.interm)-1:
                self.clear_message = self.encaps_message(self.interm[i+1].ip, self.priv_aes_key)
            else:
                self.clear_message = self.encaps_message(self.dest.ip, self.priv_aes_key)
            self.enc_key = ecies.encrypt('0x' + base64.b64decode(self.Pi).hex(), self.clear_message)
            self.frame = self.encaps_frame("key_establishment", self.enc_key)
            for j in range(i)[::-1]:
                next = {'ip': self.interm[j].ip, 'port': self.interm[j].port}
                self.clear_message = self.encaps_message(pickle.dumps(next), self.frame)
                self.enc_key = encrypt(self.clear_message, self.receiving_keys[j])
                self.frame = self.encaps_frame("relay", self.enc_key)

            send_message(self.interm[0].ip, self.interm[0].port, self.frame)
        

        # faire pareil avec la clé du noeud destinataire
        self.priv_node_key = get_private_key()
        self.clear_message = self.encaps_message("destination", self.priv_node_key)
        self.enc_key = ecies.encrypt('0x' + base64.b64decode(self.dest.key).hex(), self.clear_message)
        self.frame = self.encaps_frame("key_establishment", self.enc_key)
        for j in range(len(self.interm))[::-1]:
            next = {'ip': self.interm[j].ip, 'port': self.interm[j].port}
            self.clear_message = self.encaps_message(pickle.dumps(next), self.frame)
            self.enc_key = encrypt(self.clear_message, self.sending_keys[j])
            self.frame = self.encaps_frame("relay", self.enc_key)

        send_message(self.interm[0].ip, self.interm[0].port, self.frame)


        # envoyer toutes les clefs du retour au destinataire
        for i in range(len(self.receiving_keys)):
            self.clear_message = self.encaps_message('node_'+str(i), self.receiving_keys[i])
            self.enc_key = encrypt(self.clear_message, self.priv_node_key)
            self.frame = self.encaps_frame("key_establishment", self.enc_key)

            for j in range(len(self.interm))[::-1]:
                next = {'ip': self.interm[j].ip, 'port': self.interm[j].port}
                self.clear_message = self.encaps_message(pickle.dumps(next), self.frame)
                self.enc_key = encrypt(self.clear_message, self.sending_keys[j])
                self.frame = self.encaps_frame("relay", self.enc_key)

            send_message(self.interm[0].ip, self.interm[0].port, self.frame)

        # for debug purposes
        print(self.sending_keys)
        print(self.receiving_keys)
        print(self.priv_node_key)


