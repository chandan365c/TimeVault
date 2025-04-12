import time
from Cryptodome.PublicKey import RSA
from sender.constants import PacketType
from sender.crypto_utils import encrypt_metadata
from sender.packet_utils import create_data_packet, create_fin_packet

def handle_ack_syn(packet, state, sock):
    print("🔓 Received ACK_SYN")
    state.ack_syn_received = True


def handle_rsa_key(packet, state, sock):
    print("🔑 Received receiver's RSA key")
    rsa_key_data = packet[1:]
    state.rsa_receiver_key = RSA.import_key(rsa_key_data)  # Already validated during AES_KEY encryption step


def handle_ack_aes(packet, state, sock):
    print("✅ Received ACK_AES")
    state.ack_aes_received = True

    # Send encrypted metadata
    encrypted_meta = encrypt_metadata(state, state.delete_after)
    sock.sendto(bytes([PacketType.META]) + encrypted_meta, state.receiver_addr)
    print("📤 Sent encrypted metadata")

def handle_ack_meta(packet, state, sock):
    print("✅ Received ACK_META")
    state.ack_meta_received = True

def handle_ack(packet, state, sock):
    seq_num = int.from_bytes(packet[1:5], byteorder='big')
    if seq_num not in state.acknowledged_chunks:
        print(f"✅ ACK received for chunk {seq_num}")
        state.acknowledged_chunks.add(seq_num)
        if seq_num in state.sent_chunks:
            del state.sent_chunks[seq_num]

def handle_ack_fin(packet, state, sock):
    print("🏁 Received ACK_FIN — transfer complete.")
    state.ack_fin_received = True
    state.transfer_complete = True

def send_file_chunks(state, sock):
    base_seq = 0
    next_seq = 0
    WINDOW = state.window_size
    TIMEOUT = state.timeout

    while base_seq < len(state.file_chunks):
        # Send within sliding window
        while next_seq < base_seq + WINDOW and next_seq < len(state.file_chunks):
            if next_seq not in state.sent_chunks:
                chunk = state.file_chunks[next_seq]
                encrypted_chunk = state.encrypt_chunk(chunk)
                packet = create_data_packet(next_seq, encrypted_chunk)
                sock.sendto(packet, state.receiver_addr)
                state.sent_chunks[next_seq] = time.time()
                print(f"📨 Sent chunk {next_seq}")
            next_seq += 1

        # Retransmit timed-out packets
        now = time.time()
        for seq, sent_time in list(state.sent_chunks.items()):
            if seq not in state.acknowledged_chunks and now - sent_time > TIMEOUT:
                print(f"🔁 Retransmitting chunk {seq}")
                chunk = state.file_chunks[seq]
                encrypted_chunk = state.encrypt_chunk(chunk)
                packet = create_data_packet(seq, encrypted_chunk)
                sock.sendto(packet, state.receiver_addr)
                state.sent_chunks[seq] = now

        # Slide window
        while base_seq in state.acknowledged_chunks:
            base_seq += 1

    # Send FIN after all chunks
    print("📦 All chunks sent. Sending FIN...")
    fin_packet = create_fin_packet()
    sock.sendto(fin_packet, state.receiver_addr)
