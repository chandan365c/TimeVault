# receiver.py

import socket
import struct
import threading
import os
import time
from test_encryption import load_private_key, decrypt_aes_key, decrypt_data

HOST = "0.0.0.0"
PORT = 12345

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"🚀 Listening on {HOST}:{PORT}")

conn, addr = server.accept()
print(f"🔗 Connected by {addr}")

# Receive filename
filename_len = struct.unpack("I", conn.recv(4))[0]
filename = conn.recv(filename_len).decode()

# Receive deletion timer
delete_after = struct.unpack("I", conn.recv(4))[0]

# Receive encrypted AES key
key_len = struct.unpack("I", conn.recv(4))[0]
encrypted_key = conn.recv(key_len)

# Decrypt AES key
rsa_priv_key = load_private_key("receiver_private.pem")
aes_key = decrypt_aes_key(encrypted_key, rsa_priv_key)

# Receive encrypted file
file_len = struct.unpack("I", conn.recv(4))[0]
file_data = b""
while len(file_data) < file_len:
    file_data += conn.recv(4096)

# Decrypt and save
decrypted = decrypt_data(file_data, aes_key)
filepath = f"received_{filename}"
with open(filepath, "wb") as f:
    f.write(decrypted)

print(f"✅ Received and saved file: {filepath}")

# Timer thread to delete file
def auto_delete(path, delay):
    time.sleep(delay)
    if os.path.exists(path):
        os.remove(path)
        print(f"🗑️ Auto-deleted '{path}' after {delay} seconds.")

threading.Thread(target=auto_delete, args=(filepath, delete_after)).start()

conn.close()
server.close()
