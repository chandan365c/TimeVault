import socket
import struct
import tkinter as tk
from tkinter import filedialog
import subprocess
import time
from test_encryption import encrypt_data  # Import encryption function

HOST = "10.1.0.86"  # 🔴 Change this to the receiver’s IP
PORT = 12345

# 🔹 Step 1: Run encryption.py to generate secret.key
subprocess.run(["python3", "encryption.py"])  # Execute encryption.py
time.sleep(1)  # Give it a moment to generate secret.key

# 🔹 Step 2: Read the generated secret key
try:
    with open("secret.key", "rb") as key_file:
        secret_key = key_file.read()
except FileNotFoundError:
    print("❌ Error: secret.key not found! Make sure encryption.py is working.")
    exit()

# 🔹 Step 3: Open file picker
root = tk.Tk()
root.withdraw()  # Hide the main window
filename = filedialog.askopenfilename(title="Select a file to send")

if not filename:
    print("❌ No file selected. Exiting.")
    exit()

# 🔹 Step 4: Read and encrypt file
with open(filename, "rb") as f:
    file_data = f.read()

encrypted_data = encrypt_data(file_data)

# 🔹 Step 5: Extract only the filename (without full path)
file_name_only = filename.split("/")[-1]

# 🔹 Step 6: Connect to receiver
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# 🔹 Step 7: Send the secret.key file first (plaintext)
client_socket.send(struct.pack("I", len(secret_key)))  # Send key size
client_socket.sendall(secret_key)  # Send key data
print("[*] Secret key sent successfully.")

# 🔹 Step 8: Send filename length + filename
client_socket.send(struct.pack("I", len(file_name_only)))  # Send filename length
client_socket.send(file_name_only.encode())  # Send filename
print(f"[*] Sent filename: {file_name_only}")

# 🔹 Step 9: Send encrypted file size
client_socket.send(struct.pack("I", len(encrypted_data)))  # Send file size

# 🔹 Step 10: Send encrypted file data
client_socket.sendall(encrypted_data)  # Send actual encrypted data
print(f"✅ '{file_name_only}' has been encrypted and sent successfully!")

client_socket.close()
