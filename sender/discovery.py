import socket
import time

RECEIVER_PORT = 54321
DISCOVERY_MESSAGE = b"DISCOVER_RECEIVER"
TIMEOUT = 2

def discover_receivers(timeout=TIMEOUT):
    """
    Broadcast a UDP message to discover receivers on the local network.
    Returns a list of receivers with hostname and IP address.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    receivers = []
    try:
        sock.sendto(DISCOVERY_MESSAGE, ('<broadcast>', RECEIVER_PORT))
        start = time.time()

        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(1024)
                decoded = data.decode()
                if '|' in decoded:
                    hostname, ip = decoded.strip().split('|', 1)
                    receivers.append({
                        'hostname': hostname,
                        'ip': ip,
                        'address': addr[0],  # This is the actual source IP from the socket
                    })
            except socket.timeout:
                break
            except Exception as e:
                print(f"⚠️ Error processing response: {e}")
                continue
    finally:
        sock.close()

    return receivers
