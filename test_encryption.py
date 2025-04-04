from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# 🔹 Generate or Load AES Key
def generate_secret_key():
    key = os.urandom(32)  # AES-256 requires a 32-byte key
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

# 🔹 Load or Generate Key
if os.path.exists("secret.key"):
    with open("secret.key", "rb") as key_file:
        SECRET_KEY = key_file.read()
else:
    SECRET_KEY = generate_secret_key()

# 🔹 Encrypt Function
def encrypt_data(data):
    iv = os.urandom(16)  # Generate IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted_data  # Prepend IV for decryption

# 🔹 Decrypt Function
def decrypt_data(data, key):
    iv = data[:16]  # Extract IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(data[16:]), AES.block_size)
    return decrypted_data
