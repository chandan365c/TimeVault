import socket
import struct
import tkinter as tk
from tkinter import filedialog
from encryption import encrypt_data  # Import encryption function

HOST = "192.168.1.100"  # 🔴 Change this to the receiver’s IP
PORT = 12345

# 🔹 Open file picker
root = tk.Tk()
root.withdraw()  # Hide the main window
filename = filedialog.askopenfilename(title="Select a file to send")

if not filename:
    print("❌ No file selected. Exiting.")
    exit()

# 🔹 Read and encrypt file
with open(filename, "rb") as f:
    file_data = f.read()

encrypted_data = encrypt_data(file_data)

# 🔹 Extract only the filename (without full path)
file_name_only = filename.split("/")[-1]

# 🔹 Connect to receiver
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Send filename length + filename
client_socket.send(struct.pack("I", len(file_name_only)) + file_name_only.encode())

# Send encrypted file size
client_socket.send(struct.pack("I", len(encrypted_data)))

# Send encrypted file data
client_socket.sendall(encrypted_data)

print(f"✅ '{file_name_only}' has been encrypted and sent successfully!")

client_socket.close()