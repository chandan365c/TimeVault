from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import os

# 🔐 AES Functions
def generate_aes_key():
    key = os.urandom(32)
    with open("secret.key", "wb") as f:
        f.write(key)
    return key

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted

def decrypt_data(data, key):
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(data[16:]), AES.block_size)
    return decrypted

# 🔐 RSA Key Functions
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("receiver_private.pem", "wb") as f:
        f.write(private_key)
    with open("receiver_public.pem", "wb") as f:
        f.write(public_key)

def load_public_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def load_private_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def encrypt_aes_key(aes_key, rsa_public_key):
    cipher = PKCS1_OAEP.new(rsa_public_key)
    return cipher.encrypt(aes_key)

def decrypt_aes_key(encrypted_key, rsa_private_key):
    cipher = PKCS1_OAEP.new(rsa_private_key)
    return cipher.decrypt(encrypted_key)
