# import socket
# import struct
# import encryption

# TARGET_IP = "10.1.21.108"  # Change this to receiver's IP
# TARGET_PORT = 12345         # Custom port
# CHUNK_SIZE = 1024          # Size per packet

# def send_file(filename):
#     #sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#     sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#     with open(filename, "rb") as f:
#         seq_num = 0
#         while chunk := f.read(CHUNK_SIZE):
#             encrypted_chunk, iv = encryption.encrypt_data(chunk)
#             packet = struct.pack("!II16s", seq_num, len(encrypted_chunk), iv) + encrypted_chunk
#             sender.sendto(packet, (TARGET_IP, TARGET_PORT))
#             print(f"Sent chunk {seq_num} ({len(encrypted_chunk)} bytes)")
#             seq_num += 1

#     print("[*] File transfer complete.")

# if __name__ == "__main__":
#     file_name = input("Enter file name: ")

#     send_file("file_name.txt")

import socket
import struct
import encryption
import os

TARGET_IP = "10.1.20.154"
TARGET_PORT = 12345
CHUNK_SIZE = 1024
SRC_IP = "10.1.20.154"

KEY = encryption.KEY  # Use the generated AES key

def checksum(data):
    """Calculate checksum for IP header"""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s = s + (s >> 16)
    return ~s & 0xFFFF

def create_ip_header(source_ip, dest_ip, payload_size):
    """Manually construct an IP header"""
    total_length = 20 + 8 + payload_size
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) + 5, 0, total_length,
        os.getpid() & 0xFFFF, 0, 64, 17,  # TTL=64, Protocol=UDP (17)
        0,  # Checksum placeholder
        socket.inet_aton(source_ip),
        socket.inet_aton(dest_ip)
    )
    checksum_val = checksum(ip_header)
    return ip_header[:10] + struct.pack("H", checksum_val) + ip_header[12:]

def create_udp_header(src_port, dest_port, data):
    """Manually construct a UDP header"""
    length = 8 + len(data)
    return struct.pack("!HHHH", src_port, dest_port, length, 0)  # No checksum

def send_file(filename):
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Send AES key
    key_packet = create_ip_header(SRC_IP, TARGET_IP, len(KEY)) + create_udp_header(54321, TARGET_PORT, KEY) + KEY
    sender.sendto(key_packet, (TARGET_IP, 0))
    print("[*] Sent encryption key.")

    # Send file data
    with open(filename, "rb") as f:
        seq_num = 0
        while chunk := f.read(CHUNK_SIZE):
            encrypted_chunk, iv = encryption.encrypt_data(chunk)
            data_packet = (
                create_ip_header(SRC_IP, TARGET_IP, len(encrypted_chunk) + 24) +
                create_udp_header(54321, TARGET_PORT, encrypted_chunk) +
                struct.pack("!II16s", seq_num, len(encrypted_chunk), iv) +
                encrypted_chunk
            )
            sender.sendto(data_packet, (TARGET_IP, 0))
            print(f"Sent chunk {seq_num} ({len(encrypted_chunk)} bytes)")
            seq_num += 1

    print("[*] File transfer complete.")

if __name__ == "__main__":
    send_file("test_file.txt")

