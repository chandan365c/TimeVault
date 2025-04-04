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

# 🔹 Step 1: Receive secret key
key_size = struct.unpack("I", conn.recv(4))[0]  # Read key size
secret_key = conn.recv(key_size)  # Read key data

# 🔹 Save secret key to a file
with open("received_secret.key", "wb") as key_file:
    key_file.write(secret_key)
print("[*] Secret key received and saved.")

# 🔹 Step 2: Receive filename length and filename
filename_length = struct.unpack("I", conn.recv(4))[0]
filename = conn.recv(filename_length).decode()

# 🔹 Step 3: Receive encrypted file size
file_size = struct.unpack("I", conn.recv(4))[0]

# 🔹 Step 4: Receive encrypted file data
encrypted_data = b""
while len(encrypted_data) < file_size:
    encrypted_data += conn.recv(4096)

# 🔹 Step 5: Decrypt the file data using the received secret key
decrypted_data = decrypt_data(encrypted_data, secret_key)

# 🔹 Step 6: Save decrypted file
with open(f"received_{filename}", "wb") as f:
    f.write(decrypted_data)

print(f"✅ File '{filename}' received and decrypted successfully!")
conn.close()
server_socket.close()
