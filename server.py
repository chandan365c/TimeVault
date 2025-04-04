import socket
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time

# AES Key (must be the same as client)
KEY = b"thisisaverysecretkey"
BLOCK_SIZE = 16

# Set up server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)

print("Server is waiting for a connection...")

client_socket, addr = server_socket.accept()
print(f"Connection established with {addr}")

# Receive file size
file_size = int(client_socket.recv(1024).decode())

# Decrypt data received from the client
def decrypt_data(data, key):
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(data[BLOCK_SIZE:]), BLOCK_SIZE)
    return decrypted

# Receive and decrypt file in chunks
with open('received_file.txt', 'wb') as f:
    total_received = 0
    while total_received < file_size:
        data = client_socket.recv(1024)
        total_received += len(data)
        decrypted_data = decrypt_data(data, KEY)
        f.write(decrypted_data)

client_socket.close()
server_socket.close()
