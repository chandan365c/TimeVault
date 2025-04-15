
import socket
import threading
import tkinter as tk
from receiver.packet_dispatcher import dispatch_packet
from receiver.state_manager import ReceiverState
from receiver.crypto_utils import generate_rsa_keys
from receiver.utils import log_info
import platform

RECEIVER_PORT = 54321
BUFFER_SIZE = 65535

receiver_state = ReceiverState()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', RECEIVER_PORT))
log_info(f"📥 Listening on UDP port {RECEIVER_PORT} for file data...")

generate_rsa_keys()

class ReceiverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Receiver")
        self.running = True

        self.label = tk.Label(root, text="Receiving file...", font=("Arial", 16))
        self.label.pack(pady=20)

        # Starting a different thread for listening to packets to make sure that the gui does not "freeze" when the network operations are taking place.
        self.listen_thread = threading.Thread(target=self.listen_for_packets, daemon=True)
        self.listen_thread.start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    # Once the gui is up, we start listening for packets.
    def listen_for_packets(self):
        while self.running:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)

                if data.startswith(b"DISCOVER_RECEIVER"):
                    hostname = platform.node()
                    response = f"{hostname}|{self.get_local_ip()}"
                    sock.sendto(response.encode(), addr)
                    continue

                dispatch_packet(data, addr, sock, receiver_state)

            except Exception as e:
                if self.running:
                    print(f"⚠️ Error handling packet: {e}")

# Stop listening.
    def on_close(self):
        self.running = False
        sock.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ReceiverApp(root)
    root.mainloop()