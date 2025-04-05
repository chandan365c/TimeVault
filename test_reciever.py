import socket
import struct
import threading
import os
import time
from test_encryption import load_private_key, decrypt_aes_key, decrypt_data
import tkinter as tk
from threading import Thread
import platform

#Alert the sender with the receiver's IP
def respond_to_discovery():
    discovery_port = 50000
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", discovery_port))

    while True:
        data, addr = sock.recvfrom(1024)
        if data.decode() == "DISCOVER_RECEIVER":
            response = f"{platform.node()}|{socket.gethostbyname(socket.gethostname())}"
            sock.sendto(response.encode(), addr)

threading.Thread(target=respond_to_discovery, daemon=True).start()


HOST = "0.0.0.0"
PORT = 12345

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"🚀 Listening on {HOST}:{PORT}")

conn, addr = server.accept()
print(f"🔗 Connected by {addr}")

# Receive filename
filename_len = struct.unpack("I", conn.recv(4))[0]
filename = conn.recv(filename_len).decode()

# Receive deletion timer
delete_after = struct.unpack("I", conn.recv(4))[0]

# Receive encrypted AES key
key_len = struct.unpack("I", conn.recv(4))[0]
encrypted_key = conn.recv(key_len)

# Decrypt AES key
rsa_priv_key = load_private_key("receiver_private.pem")
aes_key = decrypt_aes_key(encrypted_key, rsa_priv_key)

# Receive encrypted file
file_len = struct.unpack("I", conn.recv(4))[0]
file_data = b""
while len(file_data) < file_len:
    file_data += conn.recv(4096)

# Decrypt and save
decrypted = decrypt_data(file_data, aes_key)
filepath = f"received_{filename}"
with open(filepath, "wb") as f:
    f.write(decrypted)

print(f"✅ Received and saved file: {filepath}")

#Show successfully received window and the auto deletion time
def show_popup(time_limit):
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    popup = tk.Toplevel()
    popup.title("File Received")

    # Make it non-resizable and always on top
    popup.resizable(False, False)
    popup.attributes('-topmost', True)

    label1 = tk.Label(popup, text="✅ File received successfully!", font=("Arial", 12))
    label1.pack(padx=20, pady=(20, 5))

    label2 = tk.Label(popup, text=f"⏳ It will be auto-deleted in {time_limit} seconds.", font=("Arial", 10))
    label2.pack(padx=20, pady=(0, 20))

    ok_button = tk.Button(popup, text="OK", command=popup.destroy)
    ok_button.pack(pady=(0, 20))

    # Position the popup in the center
    popup.update_idletasks()
    x = (popup.winfo_screenwidth() - popup.winfo_reqwidth()) // 2
    y = (popup.winfo_screenheight() - popup.winfo_reqheight()) // 2
    popup.geometry(f"+{x}+{y}")

    popup.mainloop()

# Run the popup in a separate thread to not block the main app
Thread(target=show_popup, args=(delete_after,), daemon=True).start()


# Timer thread to delete file
def auto_delete(path, delay):
    time.sleep(delay)
    if os.path.exists(path):
        os.remove(path)
        print(f"🗑️ Auto-deleted '{path}' after {delay} seconds.")

threading.Thread(target=auto_delete, args=(filepath, delete_after)).start()

conn.close()
server.close()
