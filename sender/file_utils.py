import os
import json
import time
from sender.constants import CHUNK_SIZE, WINDOW_SIZE, TIMEOUT
from sender.packet_utils import create_data_packet, create_fin_packet

def read_file_chunks(file_path):
    """
    Reads a file and returns a list of chunks.
    """
    chunks = []
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
    return chunks

def get_file_metadata(file_path, ttl_seconds):
    """
    Builds metadata dictionary for the file.
    """
    filename = os.path.basename(file_path)
    filesize = os.path.getsize(file_path)

    return {
        "filename": filename,
        "filesize": filesize,
        "ttl": ttl_seconds
    }

def serialize_metadata(metadata, aes_cipher):
    """
    Encrypts metadata using AES cipher.
    """
    meta_bytes = json.dumps(metadata).encode()
    nonce = aes_cipher.nonce
    ciphertext = aes_cipher.encrypt(meta_bytes)
    return nonce + ciphertext

def split_and_encrypt_file(state):
    """
    Splits the file and AES-encrypts each chunk.
    Updates the state with encrypted chunks and chunk count.
    """
    chunks = read_file_chunks(state.filepath)
    encrypted_chunks = []

    for chunk in chunks:
        encrypted_chunk = state.aes_cipher.encrypt(chunk)
        encrypted_chunks.append(encrypted_chunk)

    state.encrypted_chunks = encrypted_chunks
    state.total_chunks = len(encrypted_chunks)
    state.filesize = os.path.getsize(state.filepath)
    print(f"📦 File split and encrypted into {state.total_chunks} chunks.")

def send_chunks_with_sliding_window(sock, addr, state):
    """
    Sends file chunks using a sliding window and handles ACK-based retransmissions.
    """
    base = 0
    next_seq = 0
    total_chunks = state.total_chunks
    unacked = {}

    def retransmit(seq_num):
        if seq_num in unacked:
            packet = create_data_packet(seq_num, state.encrypted_chunks[seq_num])
            sock.sendto(packet, addr)
            unacked[seq_num] = time.time()
            print(f"🔁 Retransmitted chunk #{seq_num}")

    while base < total_chunks:
        while next_seq < base + WINDOW_SIZE and next_seq < total_chunks:
            packet = create_data_packet(next_seq, state.encrypted_chunks[next_seq])
            sock.sendto(packet, addr)
            unacked[next_seq] = time.time()
            print(f"📤 Sent chunk #{next_seq}")
            next_seq += 1

        # Handle ACKs and timeouts
        current_time = time.time()
        for seq, ts in list(unacked.items()):
            if current_time - ts > TIMEOUT:
                retransmit(seq)

        while base in state.received_acks:
            unacked.pop(base, None)
            base += 1

        time.sleep(0.05)

    # Send FIN
    fin_packet = create_fin_packet()
    sock.sendto(fin_packet, addr)
    print("✅ File transfer complete. FIN packet sent.")
