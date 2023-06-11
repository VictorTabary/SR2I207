import secrets
import string
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib


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
        s.send(message + b'\n')
        while s.recv(1024) != b'ACK':
            print('tjrs pas')
            s.send(message + b'\n')
    except:
        print("Host down")