import secrets
import string
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib
import pickle
import ecies
from config import F_PACKET_SIZE


PASSWORD_SIZE = 15
BLOCK_SIZE = 16
pad = lambda s: s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)).encode()
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


def service_name(key):
    return base64.b32encode(hashlib.sha1(key).digest()).decode().lower()


def send_message(s, message):
    try:
        s.send(int(len(message)).to_bytes(F_PACKET_SIZE, 'big') + message)
    except Exception as e:
        print("Host down or bad message : ", e)


def encaps_frame(action, message):
    return pickle.dumps({'action': action, 'message': message})


def build_send_message(s, action, cipher, cipher_key, info, message, sending_keys, node_id):

    if cipher == "ECIES":
        message = pickle.dumps({'info': info, 'm': message})
        frame = encaps_frame(action, message)
        enc_message = ecies.encrypt('0x' + base64.b64decode(cipher_key).hex(), frame)
    else:
        frame = encaps_frame(action, message)
        enc_message = encrypt(frame, cipher_key)

    # On chiffre successivement avec toutes les clés d'envoi

    for j in range(node_id)[::-1]:
        frame = encaps_frame("relay", enc_message)
        enc_message = encrypt(frame, sending_keys[j])

    # l'envoyer au destinataire
    send_message(s, enc_message)


def listen(conn):
    # écouter tant qu'on n'a pas 4 octets
    data = b''
    while len(data) != F_PACKET_SIZE:
        data += conn.recv(F_PACKET_SIZE - len(data))
    packet_size = int.from_bytes(data, 'big')

    # écouter tant qu'on a pas le packet complet
    packet = b''
    while len(packet) != packet_size:
        packet += conn.recv(packet_size - len(packet))

    return packet
