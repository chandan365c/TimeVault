# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding
# from cryptography.hazmat.backends import default_backend
# import os

# KEY = os.urandom(32)  # 256-bit AES key
# # Fixed Key (In real-world, use key exchange or store securely)
# #KEY = b"thisisaverysecurekey1234567890!!"

# def encrypt_data(data):
#     IV = os.urandom(16)  # Generate a new IV for each chunk
#     padder = padding.PKCS7(128).padder()
#     padded_data = padder.update(data) + padder.finalize()

#     cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(padded_data) + encryptor.finalize()

#     return ciphertext, IV  # Return IV separately

# def decrypt_data(encrypted_data, iv):
#     cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
#     decryptor = cipher.decryptor()
#     decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

#     unpadder = padding.PKCS7(128).unpadder()
#     plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

#     return plaintext


# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding
# from cryptography.hazmat.backends import default_backend
# import os

# KEY = os.urandom(32)  # 256-bit AES key

# def encrypt_data(data):
#     IV = os.urandom(16)  # Generate a random IV per chunk
#     padder = padding.PKCS7(128).padder()
#     padded_data = padder.update(data) + padder.finalize()

#     cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(padded_data) + encryptor.finalize()

#     return ciphertext, IV  # Return IV separately

# def decrypt_data(encrypted_data, iv, key):
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
#     decryptor = cipher.decryptor()
#     decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

#     print(f"[DEBUG] Decrypted (before unpad): {decrypted_padded.hex()}")  # Debug

#     unpadder = padding.PKCS7(128).unpadder()
#     plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

#     return plaintext

# def set_key(new_key):
#     """Sets the decryption key when received from sender."""
#     global KEY
#     KEY = new_key

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
def decrypt_data(data):
    iv = data[:16]  # Extract IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(data[16:]), AES.block_size)
    return decrypted_data