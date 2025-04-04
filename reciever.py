# import socket
# import struct
# import encryption

# LISTEN_IP = "0.0.0.0"  # Receiver's IP
# PORT = 12345
# BUFFER_SIZE = 2048

# def receive_file(output_file):
#     #receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#     receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     receiver.bind((LISTEN_IP, PORT))

#     with open(output_file, "wb") as f:
#         while True:
#             packet, addr = receiver.recvfrom(BUFFER_SIZE)
#             seq_num, data_length, iv = struct.unpack("!II16s", packet[:24])
#             encrypted_data = packet[24:24 + data_length]

#             decrypted_data = encryption.decrypt_data(encrypted_data, iv)
#             f.write(decrypted_data)

#             print(f"Received chunk {seq_num} ({data_length} bytes)")

# if __name__ == "__main__":
#     receive_file("received.txt")

import socket
import struct
import encryption

LISTEN_IP = "0.0.0.0"
PORT = 12345
BUFFER_SIZE = 2048

def receive_file():
    receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    receiver.bind((LISTEN_IP, PORT))

    # Step 1: Receive AES Key
    packet, addr = receiver.recvfrom(BUFFER_SIZE)
    key_data = packet[-32:]  # Last 32 bytes are the AES key
    encryption.set_key(key_data)
    print("[*] Received encryption key.")

    # Step 2: Receive File Content (Always save as 'received.txt')
    with open("received.txt", "wb") as f:
        while True:
            packet, addr = receiver.recvfrom(BUFFER_SIZE)
            udp_payload = packet[28:]  # Skip IP and UDP headers

            seq_num, data_length, iv = struct.unpack("!II16s", udp_payload[:24])
            encrypted_data = udp_payload[24:24 + data_length].ljust((data_length + 15) // 16 * 16, b'\x00')

            #print(f"[*] Received Encrypted Chunk: {len(encrypted_data)} bytes")

            decrypted_data = encryption.decrypt_data(encrypted_data, iv, key_data)
            f.write(decrypted_data)

            print(f"Received chunk {seq_num} ({data_length} bytes)")

if __name__ == "__main__":
    receive_file()

