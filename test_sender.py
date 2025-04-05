import socket
import struct
import tkinter as tk
from tkinter import filedialog
from test_encryption import encrypt_data, load_public_key, encrypt_aes_key, generate_rsa_keys
import os
import time

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

# Call the function to find out receivers in local network
receivers = discover_receivers()
if not receivers:
    print("❌ No receivers found on the network.")
    exit()

print("\nAvailable receivers:")
for i, (name, ip) in enumerate(receivers):
    print(f"{i+1}. {name} ({ip})")

choice = int(input("Select a receiver to send the file to: ")) - 1
receiver_ip = receivers[choice][1]

generate_rsa_keys()
print("✅ RSA key pair generated: 'receiver_public.pem' and 'receiver_private.pem'")

HOST = receiver_ip
PORT = 12345

# GUI for file and timer input
root = tk.Tk()
root.withdraw()
filename = filedialog.askopenfilename(title="Select file to send")

if not filename:
    print("❌ No file selected. Exiting.")
    exit()

delete_after = int(input("🕒 Enter auto-deletion time (in seconds): "))

with open(filename, "rb") as f:
    file_data = f.read()

aes_key = os.urandom(32)
encrypted_file_data = encrypt_data(file_data, aes_key)

rsa_pub_key = load_public_key("receiver_public.pem")
encrypted_aes_key = encrypt_aes_key(aes_key, rsa_pub_key)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

file_name_only = os.path.basename(filename)

# Send metadata: filename + timer
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