import os
import time
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from sender.state_manager import SenderState
from sender.crypto_utils import generate_aes_key_and_nonce, encrypt_aes_key_with_rsa
from sender.file_utils import read_file_chunks
from sender.constants import PacketType
from sender.packet_dispatcher import dispatch_packet
from sender.packet_handlers import send_file_chunks
from sender.discovery import discover_receivers

RECEIVER_PORT = 54321
BUFFER_SIZE = 65535

state = SenderState()

class SenderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Sender")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(state.timeout)

        self.create_widgets()

    def create_widgets(self):
        self.root.configure(bg="grey")
        # Discover Receivers Button
        self.discover_button = tk.Button(self.root, text="Discover Receivers", command=self.discover_receivers)
        self.discover_button.pack(pady=10)

        # Receiver List
        self.receiver_listbox = tk.Listbox(self.root, width=50, height=10, bg="black", fg="white", )
        self.receiver_listbox.pack(pady=10, anchor="center")

        # Select Receiver Button
        self.select_receiver_button = tk.Button(self.root, text="Select Receiver", command=self.select_receiver)
        self.select_receiver_button.pack(pady=10)

        # Select File Button
        self.select_file_button = tk.Button(self.root, text="Select File", command=self.select_file, state=tk.DISABLED)
        self.select_file_button.pack(pady=10)

        # Enter Deletion Time Button
        self.enter_time_button = tk.Button(self.root, text="Enter Deletion Time", command=self.enter_deletion_time, state=tk.DISABLED)
        self.enter_time_button.pack(pady=10)

    def discover_receivers(self):
        self.receivers = discover_receivers()
        self.receiver_listbox.delete(0, tk.END)

        if not self.receivers:
            messagebox.showerror("Error", "No receivers found.")
            return

        for receiver in self.receivers:
            self.receiver_listbox.insert(tk.END, f"{receiver['hostname']} ({receiver['ip']})")

    def select_receiver(self):
        selected_index = self.receiver_listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "Please select a receiver.")
            return

        receiver = self.receivers[selected_index[0]]
        state.receiver_addr = (receiver['ip'], RECEIVER_PORT)
        messagebox.showinfo("Receiver Selected", f"Selected receiver: {receiver['hostname']} ({receiver['ip']})")
        self.select_file_button.config(state=tk.NORMAL)

    def select_file(self):
        filepath = filedialog.askopenfilename(title="Select file to send")
        if not filepath:
            messagebox.showerror("Error", "No file selected.")
            return

        state.filename = os.path.basename(filepath)
        state.file_chunks = read_file_chunks(filepath)
        state.filesize = sum(len(chunk) for chunk in state.file_chunks)
        messagebox.showinfo("File Selected", f"Selected file: {state.filename}")
        self.enter_time_button.config(state=tk.NORMAL)

    def enter_deletion_time(self):
        deletion_time = simpledialog.askinteger("Deletion Time", "Enter auto-deletion time (in seconds):")
        if deletion_time is None:
            messagebox.showerror("Error", "No deletion time entered.")
            return

        state.delete_after = deletion_time
        messagebox.showinfo("Deletion Time Set", f"Auto-deletion time set to {state.delete_after} seconds.")
        self.start_transfer()

    def start_transfer(self):
        # Start ACK Listener Thread
        ack_thread = threading.Thread(target=self.listen_for_acks, daemon=True)
        ack_thread.start()

        # Starting the protocol sequence
        self.sock.sendto(bytes([PacketType.SYN]), state.receiver_addr)
        self.wait_for_ack("ACK_SYN", lambda: state.ack_syn_received)

        generate_aes_key_and_nonce(state)
        encrypted_aes_key = encrypt_aes_key_with_rsa(state)
        self.sock.sendto(bytes([PacketType.RSA_KEY]) + encrypted_aes_key, state.receiver_addr)

        self.wait_for_ack("ACK_AES", lambda: state.ack_aes_received)
        self.wait_for_ack("ACK_META", lambda: state.ack_meta_received)

        # Start File Transfer
        file_thread = threading.Thread(target=self.transfer_file)
        file_thread.start()
        file_thread.join()

        self.wait_for_ack("ACK_FIN", lambda: state.ack_fin_received)
        messagebox.showinfo("Success", "File transfer completed successfully.")

    def listen_for_acks(self):
        while not state.transfer_complete:
            try:
                data, _ = self.sock.recvfrom(BUFFER_SIZE)
                dispatch_packet(data, state, self.sock)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"⚠️ Error in ACK listener: {e}")

    def wait_for_ack(self, ack_name, condition):
        while not condition():
            time.sleep(0.1)

    def transfer_file(self):
        send_file_chunks(state, self.sock)

if __name__ == "__main__":
    root = tk.Tk()
    app = SenderApp(root)
    root.mainloop()