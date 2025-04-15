import socket
import threading
import platform
from receiver.packet_dispatcher import dispatch_packet
from receiver.state_manager import ReceiverState
from receiver.crypto_utils import generate_rsa_keys
from receiver.utils import log_info

RECEIVER_PORT = 54321
BUFFER_SIZE = 65535

receiver_state = ReceiverState()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', RECEIVER_PORT))
log_info(f"📥 Listening on UDP port {RECEIVER_PORT} for file data...")

generate_rsa_keys()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def listen_for_packets():
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)

            if data.startswith(b"DISCOVER_RECEIVER"):
                response = f"{platform.node()}|{get_local_ip()}"
                sock.sendto(response.encode(), addr)
                continue

            dispatch_packet(data, addr, sock, receiver_state)

        except Exception as e:
            print(f"⚠️ Error handling packet: {e}")

listen_thread = threading.Thread(target=listen_for_packets, daemon=True)
listen_thread.start()

while True:
    try:
        pass
    except KeyboardInterrupt:
        log_info("\n🔌 Receiver shutting down.")
        sock.close()
        break
