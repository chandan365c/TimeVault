import socket
import struct
from test_encryption import decrypt_data  # Import decryption function

HOST = "0.0.0.0"  # Listen on all interfaces
PORT = 12345

# 🔹 Set up the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f"🚀 Server listening on {HOST}:{PORT}")

conn, addr = server_socket.accept()
print(f"🔗 Connected by {addr}")

# 🔹 Receive filename length and filename
filename_length = struct.unpack("I", conn.recv(4))[0]
filename = conn.recv(filename_length).decode()

# 🔹 Receive encrypted file size
file_size = struct.unpack("I", conn.recv(4))[0]

# 🔹 Receive encrypted file data
encrypted_data = b""
while len(encrypted_data) < file_size:
    encrypted_data += conn.recv(4096)

# 🔹 Decrypt the file data
decrypted_data = decrypt_data(encrypted_data)

# 🔹 Save decrypted file
with open(f"received_{filename}", "wb") as f:
    f.write(decrypted_data)

print(f"✅ File '{filename}' received and decrypted successfully")
conn.close()
server_socket.close()