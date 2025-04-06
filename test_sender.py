import socket
import struct
import tkinter as tk
from tkinter import filedialog
from test_encryption import encrypt_data, encrypt_aes_key
import os
import time
from Crypto.PublicKey import RSA

def discover_receivers(timeout=3):
    message = "DISCOVER_RECEIVER"
    discovery_port = 50000
    responses = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    sock.sendto(message.encode(), ('<broadcast>', discovery_port))
    start = time.time()

    try:
        while time.time() - start < timeout:
            data, addr = sock.recvfrom(1024)
            name, ip = data.decode().split("|")
            responses.append((name, ip))
    except socket.timeout:
        pass
    finally:
        sock.close()

    return responses

# Discover receivers
receivers = discover_receivers()
if not receivers:
    print("❌ No receivers found on the network.")
    exit()

print("\nAvailable receivers:")
for i, (name, ip) in enumerate(receivers):
    print(f"{i+1}. {name} ({ip})")

choice = int(input("Select a receiver to send the file to: ")) - 1
receiver_ip = receivers[choice][1]

HOST = receiver_ip
PORT = 12345

# File and timer input
root = tk.Tk()
root.withdraw()
filename = filedialog.askopenfilename(title="Select file to send")

if not filename:
    print("❌ No file selected. Exiting.")
    exit()

delete_after = int(input("🕒 Enter auto-deletion time (in seconds): "))

with open(filename, "rb") as f:
    file_data = f.read()

# Connect to receiver
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Receive receiver's public RSA key
key_len_data = client.recv(4)
if len(key_len_data) < 4:
    raise Exception("Failed to receive key length.")

key_len = struct.unpack("I", key_len_data)[0]
receiver_pubkey_data = b""
while len(receiver_pubkey_data) < key_len:
    receiver_pubkey_data += client.recv(key_len - len(receiver_pubkey_data))

print("✅ Received receiver's public RSA key.")

# Load public key
rsa_pub_key = RSA.import_key(receiver_pubkey_data)

# Encrypt file and AES key
aes_key = os.urandom(32)
encrypted_file_data = encrypt_data(file_data, aes_key)
encrypted_aes_key = encrypt_aes_key(aes_key, rsa_pub_key)

file_name_only = os.path.basename(filename)

# Send filename and timer
client.send(struct.pack("I", len(file_name_only)))
client.send(file_name_only.encode())
client.send(struct.pack("I", delete_after))

# Send encrypted AES key
client.send(struct.pack("I", len(encrypted_aes_key)))
client.send(encrypted_aes_key)

# Send encrypted file data
client.send(struct.pack("I", len(encrypted_file_data)))
client.sendall(encrypted_file_data)

print(f"✅ '{file_name_only}' sent with {delete_after}s auto-deletion")
client.close()
