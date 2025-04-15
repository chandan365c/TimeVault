import os
import socket
import time
import threading
import tkinter as tk
from tkinter import filedialog
from sender.state_manager import SenderState
from sender.crypto_utils import generate_aes_key_and_nonce, encrypt_aes_key_with_rsa
from sender.file_utils import read_file_chunks
from sender.constants import PacketType
from sender.packet_dispatcher import dispatch_packet
from sender.packet_handlers import send_file_chunks
from sender.discovery import discover_receivers

# === Config ===
RECEIVER_PORT = 54321
BUFFER_SIZE = 65535

# === Setup State ===
state = SenderState()
print("📡 Scanning for receivers on local network...")
receivers = discover_receivers()

if not receivers:
    print("❌ No receivers found. Exiting.")
    exit(1)

# === Select Receiver ===
print("\nAvailable receivers:")
for i, receiver in enumerate(receivers):
    name = receiver['hostname']
    ip = receiver['ip']
    print(f"{i+1}. {name} ({ip})")

choice = int(input("Select a receiver to send the file to: ")) - 1
receiver = receivers[choice]  # Get the selected receiver's dictionary
receiver_ip = receiver['ip']  # Access the 'ip' key from the dictionary
state.receiver_addr = (receiver_ip, RECEIVER_PORT)

print(f"✅ Selected receiver: {receiver['hostname']} ({receiver_ip})")


# === SELECT FILE ===
root = tk.Tk()
root.withdraw()
filepath = filedialog.askopenfilename(title="Select file to send")
state.filename = os.path.basename(filepath)
state.file_chunks = read_file_chunks(state.filename)
state.filesize = sum(len(chunk) for chunk in state.file_chunks)

# === AUTO DELETION TIME ===
state.delete_after = int(input("🕒 Enter auto-deletion time (in seconds): "))

# === Setup Socket ===
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(state.timeout)

# === Start ACK Listener Thread ===
def listen_for_acks():
    while not state.transfer_complete:
        try:
            data, _ = sock.recvfrom(BUFFER_SIZE)
            dispatch_packet(data, state, sock)
        except socket.timeout:
            continue
        except Exception as e:
            print(f"⚠️ Error in ACK listener: {e}")

ack_thread = threading.Thread(target=listen_for_acks, daemon=True)
ack_thread.start()

# === Begin Protocol Sequence ===

# Send SYN
print("📨 Sending SYN...")
sock.sendto(bytes([PacketType.SYN]), state.receiver_addr)

# Wait for ACK_SYN
print("⏳ Waiting for ACK_SYN...")
while not state.ack_syn_received:
    time.sleep(0.1)

# Wait for RSA_KEY
#print("⏳ Waiting for receiver's RSA key...")
while not state.rsa_receiver_key:
    time.sleep(0.1)

# Generate AES key and nonce
generate_aes_key_and_nonce(state)
    
encrypted_aes_key = encrypt_aes_key_with_rsa(state)
sock.sendto(bytes([PacketType.RSA_KEY]) + encrypted_aes_key, state.receiver_addr)
print("🔐 Sent AES key (encrypted with RSA key)")

#FOR DEBUGGING
#print(f"[DEBUG] RSA_KEY packet size: {1 + len(encrypted_aes_key)} (1 byte header + {len(encrypted_aes_key)} byte payload)")

# Send AES key will be handled by ACK_SYN handler

# Wait for ACK_AES
print("⏳ Waiting for ACK_AES...")
while not state.ack_aes_received:
    time.sleep(0.1)

# Send metadata handled by ACK_AES handler

# Wait for ACK_META
print("⏳ Waiting for ACK_META...")
while not state.ack_meta_received:
    time.sleep(0.1)

# === Start File Transfer in Thread ===
def transfer_thread():
    print("📦 Starting file transfer...")
    send_file_chunks(state, sock)

file_thread = threading.Thread(target=transfer_thread)
file_thread.start()

# Wait for file transfer to complete
file_thread.join()

# Wait for ACK_FIN
print("⏳ Waiting for ACK_FIN...")
while not state.ack_fin_received:
    time.sleep(0.1)

print("✅ File transfer completed successfully.... Closed connection")
