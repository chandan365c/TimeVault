import socket
import struct
import tkinter as tk
from tkinter import filedialog
from test_encryption import encrypt_data, encrypt_aes_key, generate_aes_key
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
aes_key = generate_aes_key()
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


# import socket
# import struct
# import os
# from test_encryption import encrypt_data, encrypt_aes_key
# from Crypto.PublicKey import RSA

# def create_packet(packet_type, payload):
#     return packet_type + payload  # Simple: 4-byte header + data

# def send_raw_packet(dest_ip, payload):
#     sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

#     # IP header will be auto-filled by OS if we use IPPROTO_RAW
#     sock.sendto(payload, (dest_ip, 0))

# # === Prepare data ===
# filename = "my_secret.pdf"
# delete_after = 10

# with open(filename, "rb") as f:
#     data = f.read()

# aes_key = os.urandom(32)
# encrypted_data = encrypt_data(data, aes_key)

# rsa_pub_key = RSA.import_key(open("receiver_public.pem", "rb").read())
# encrypted_aes_key = encrypt_aes_key(aes_key, rsa_pub_key)

# dest_ip = "192.168.0.101"  # Set receiver IP manually

# # === Send packets ===
# send_raw_packet(dest_ip, create_packet(b'META', struct.pack("I", delete_after) + filename.encode()))
# send_raw_packet(dest_ip, create_packet(b'KEY_', encrypted_aes_key))

# # Break data into chunks
# chunk_size = 1400
# for i in range(0, len(encrypted_data), chunk_size):
#     chunk = encrypted_data[i:i+chunk_size]
#     send_raw_packet(dest_ip, create_packet(b'DATA', chunk))

# send_raw_packet(dest_ip, create_packet(b'END_', b'done'))

# print("✅ Sent via raw sockets.")
