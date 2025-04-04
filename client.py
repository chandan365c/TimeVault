import socket
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import tkinter as tk
from tkinter import filedialog
import threading
import time

# AES Encryption Setup
KEY = b"thisisaverysecretkey"  # 16-byte key for AES
BLOCK_SIZE = 16

# Set up the client socket
def send_file(file_path, host='localhost', port=12345):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Read file and get its size
    file_size = os.path.getsize(file_path)
    
    # Encrypt the file before sending
    def encrypt_data(data, key):
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted = cipher.encrypt(pad(data, BLOCK_SIZE))
        return cipher.iv + encrypted  # Include the IV for decryption

    # Send file size to the server
    client_socket.send(str(file_size).encode())

    # Open file and send it in chunks
    with open(file_path, 'rb') as f:
        while chunk := f.read(1024):
            encrypted_chunk = encrypt_data(chunk, KEY)
            client_socket.send(encrypted_chunk)

    client_socket.close()

# File Selection Function
def select_file():
    file_path = filedialog.askopenfilename(title="Select a file to send")
    file_entry.delete(0, tk.END)  # Clear previous entry
    file_entry.insert(0, file_path)  # Insert the selected file path

# Start file transfer with progress
def start_transfer():
    file_path = file_entry.get()
    if not file_path:
        print("No file selected")
        return

    # Start transfer in a separate thread to keep the UI responsive
    threading.Thread(target=send_file_with_progress, args=(file_path,)).start()

# Send file with progress bar and timer
def send_file_with_progress(file_path):
    # Start the transfer in a separate thread
    send_file(file_path)

    # Here we simulate progress. Update with actual transfer progress as needed.
    for i in range(101):
        progress_var.set(i)
        time.sleep(0.05)  # Simulating file transfer progress (adjust accordingly)

    # Start a timer to delete file after 60 seconds
    start_delete_timer()

# Timer to delete the file after 60 seconds
def start_delete_timer():
    time.sleep(60)  # Wait for 60 seconds
    file_path = file_entry.get()
    if os.path.exists(file_path):
        os.remove(file_path)  # Secure delete method can be added here
        print(f"File {file_path} deleted after timer expired.")
        progress_var.set(0)  # Reset progress bar

# Set up the Tkinter window
root = tk.Tk()
root.title("Secure File Transfer")

# File selection UI
file_label = tk.Label(root, text="Select File:")
file_label.pack(padx=10, pady=5)
file_entry = tk.Entry(root, width=40)
file_entry.pack(padx=10, pady=5)
select_button = tk.Button(root, text="Select File", command=select_file)
select_button.pack(padx=10, pady=5)

# Progress bar UI
progress_var = tk.IntVar()
progress_bar = tk.Progressbar(root, variable=progress_var, maximum=100, length=300)
progress_bar.pack(padx=10, pady=10)

# Send button UI
send_button = tk.Button(root, text="Send File", command=start_transfer)
send_button.pack(padx=10, pady=10)

# Start the Tkinter event loop
root.mainloop()
