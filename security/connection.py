import base64
import socket
import ecies
import pickle
from security.utils import *
from threading import Thread
from secp256k1 import PrivateKey



def send_message(s, message):
    try:
        s.send(message + b'\n')
        while s.recv(1024) != b'ACK':
            print('tjrs pas')
            s.send(message + b'\n')
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
        aes_key_to, aes_key_back = b'', b''
        aes_node_key = b''
        from_addr, to_addr = {}, {}
        sock = ''
        EXTREMITY = False

        # utilisés seulement si extrémité
        receiving_keys = []
        while True:
            try:
                data = conn.recv(2048)
                if data:
                    frame = pickle.loads(data)
                    print(frame)
                    if frame["action"] == "key_establishment" and EXTREMITY == False:
                        message = pickle.loads(ecies.decrypt(self.privkey, frame["enc_message"]))
                        #print(message)
                        dest = message['dest']                      
                        if dest['ip'] == 'to':
                            aes_key_to = message['m']
                            from_addr = {'ip': addr[0], 'port': addr[1]}
                            print("\nCLE ALLER:", aes_key_to, '\n')

                        elif dest['ip'] == "destination":
                            EXTREMITY = True    # pour gérer le cas spécial où on est extrémité de la connexion
                            aes_node_key = message['m']
                            from_addr = {'ip': addr[0], 'port': addr[1]}
                            print("\nCLE DU NOEUD:", aes_node_key, '\n')
                        
                        else:
                            aes_key_back = message['m']
                            to_addr = message['dest']
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                sock.connect((to_addr['ip'], to_addr['port']))
                            except:
                                print("Can't contact the next node")
                            print("\nCLE RETOUR:", aes_key_back, '\n')
                    
                    elif EXTREMITY and frame["action"] == "key_establishment":
                        message = pickle.loads(decrypt(frame["enc_message"], aes_node_key))
                        receiving_keys.append(message['m'])

                        print('\n', receiving_keys)
                        print("je suis une extrémité de la connexion (mais je ne suis pas implémenté pour le moment)\n")
                    

                    # mettre des headers "relay_to" et "relay_from" pour savoir avec quelle clé déchiffrer le paquet
                    elif frame["action"] == "relay_to":
                        decr_message = decrypt(frame["enc_message"], aes_key_to)
                        message = pickle.loads(decr_message)
                        send_message(sock, message['m'])


                    conn.send(b"ACK")

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

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.interm[0].ip, self.interm[0].port))
        except:
            print('Host seems down')

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
            next = {'ip': 'to', 'port': 0}
            self.clear_message = self.encaps_message(next, self.priv_aes_key)
            self.enc_key = ecies.encrypt('0x' + base64.b64decode(self.Pi).hex(), self.clear_message)
            self.frame = self.encaps_frame("key_establishment", self.enc_key)
            for j in range(i)[::-1]:
                next = {'ip': self.interm[j].ip, 'port': self.interm[j].port}
                self.clear_message = self.encaps_message(next, self.frame)
                self.enc_key = encrypt(self.clear_message, self.sending_keys[j])
                self.frame = self.encaps_frame("relay_to", self.enc_key)
            # l'envoyer au destinataire
            send_message(self.s, self.frame)


            # faire pareil avec les clés de déchiffrement au retour            
            self.priv_aes_key = get_private_key()
            self.receiving_keys.append(self.priv_aes_key)
            if i < len(self.interm)-1:
                next = {'ip': self.interm[i+1].ip, 'port': self.interm[i+1].port}
            else:
                next = {'ip': self.dest.ip, 'port': self.dest.port}
            self.clear_message = self.encaps_message(next, self.priv_aes_key)
            self.enc_key = ecies.encrypt('0x' + base64.b64decode(self.Pi).hex(), self.clear_message)
            self.frame = self.encaps_frame("key_establishment", self.enc_key)
            for j in range(i)[::-1]:
                next = {'ip': self.interm[j].ip, 'port': self.interm[j].port}
                self.clear_message = self.encaps_message(next, self.frame)
                self.enc_key = encrypt(self.clear_message, self.sending_keys[j])
                self.frame = self.encaps_frame("relay_to", self.enc_key)

            send_message(self.s, self.frame)
        

        # faire pareil avec la clé du noeud destinataire
        self.priv_node_key = get_private_key()
        next = {'ip': 'destination', 'port': 0}
        self.clear_message = self.encaps_message(next, self.priv_node_key)
        self.enc_key = ecies.encrypt('0x' + base64.b64decode(self.dest.key).hex(), self.clear_message)
        self.frame = self.encaps_frame("key_establishment", self.enc_key)
        for j in range(len(self.interm))[::-1]:
            next = {'ip': self.interm[j].ip, 'port': self.interm[j].port}
            self.clear_message = self.encaps_message(next, self.frame)
            self.enc_key = encrypt(self.clear_message, self.sending_keys[j])
            self.frame = self.encaps_frame("relay_to", self.enc_key)

        send_message(self.s, self.frame)


        # envoyer toutes les clefs du retour au destinataire
        for i in range(len(self.receiving_keys)):
            next = {'ip': self.interm[i].ip, 'port': self.interm[i].port}
            self.clear_message = self.encaps_message(next, self.receiving_keys[i])
            self.enc_key = encrypt(self.clear_message, self.priv_node_key)
            self.frame = self.encaps_frame("key_establishment", self.enc_key)

            for j in range(len(self.interm))[::-1]:
                next = {'ip': "back", 'port': 0}
                self.clear_message = self.encaps_message(next, self.frame)
                self.enc_key = encrypt(self.clear_message, self.sending_keys[j])
                self.frame = self.encaps_frame("relay_to", self.enc_key)

            send_message(self.s, self.frame)

        # for debug purposes
        print(self.sending_keys)
        print(self.receiving_keys)
        print(self.priv_node_key)

        self.s.close()


