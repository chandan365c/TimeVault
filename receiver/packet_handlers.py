import struct
import json
from receiver.state_manager import ReceiverState
from receiver.crypto_utils import decrypt_aes_key_packet
from receiver.utils import log_info, log_warn, log_error, log_success, show_gui_popup
from receiver.constants import CHUNK_SIZE, PacketType
from Crypto.Cipher import AES
from receiver.file_utils import save_chunk_to_file


def handle_syn(packet: bytes, addr, state: ReceiverState, sock):
    if state.connected:
        log_warn("Received SYN but already connected. Ignoring.")
        return

    log_info(f"🔗 Connection request from {addr}")
    state.sender_addr = addr
    state.connected = True
    state.state = "AWAITING_AES_KEY"

    # Respond with ACK_SYN
    sock.sendto(struct.pack("!B", PacketType.ACK_SYN), addr)
    log_info(f"🔗 Connected to {addr}")

    # Send public RSA key
    try:
        with open(state.public_key_path, 'rb') as f:
            public_key_data = f.read()
        sock.sendto(struct.pack("!B", PacketType.RSA_KEY) + public_key_data, addr)
        log_info("📤 Sent public RSA key to sender.")
    except Exception as e:
        log_error(f"❌ Failed to send public RSA key: {e}")
        state.reset()


def handle_rsa_key(packet: bytes, addr, state: ReceiverState, sock):
    print("🔐 Received AES key (encrypted with RSA_KEY)")
    encrypted_key = packet[1:]

    #FOR DEBUGGING
    #print(f"[DEBUG] Received RSA_KEY packet size: {len(packet)}")
    #print(f"[DEBUG] Encrypted key length: {len(packet[1:])}")

    # Decrypt AES key
    try:
        aes_key, nonce = decrypt_aes_key_packet(encrypted_key)
        state.aes_key = aes_key
        state.aes_nonce = nonce
        print("✅ AES key and nonce decrypted.")

        state.state = "AWAITING_META" 

        # Send ACK_AES
        sock.sendto(struct.pack("!B", PacketType.ACK_AES), addr)
        print("📤 Sent ACK_AES")

    except Exception as e:
        print(f"❌ Failed to decrypt AES key: {e}")


def handle_meta(packet: bytes, addr, state: ReceiverState, sock):
    if not state.connected or state.state != "AWAITING_META":
        log_warn("Unexpected META packet. Ignoring.")
        return

    try:
        encrypted_meta = packet[1:]  # Skip PacketType byte
        nonce = encrypted_meta[:16]
        tag = encrypted_meta[16:32]
        ciphertext = encrypted_meta[32:]

        cipher = AES.new(state.aes_key, AES.MODE_EAX, nonce=nonce)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            metadata = json.loads(decrypted.decode())
        except ValueError:
            log_error("❌ Metadata decryption failed: tag mismatch!")
            return
        

        state.filename = metadata["filename"]
        state.filesize = metadata["filesize"]
        state.ttl = metadata.get("ttl", 60)
        state.expected_chunks = (state.filesize + CHUNK_SIZE - 1) // CHUNK_SIZE
        state.received_chunks = {}
        state.state = "RECEIVING_FILE"

        log_success(f"📄 Metadata received: {metadata}")
        show_gui_popup("Receiving File", f"File: {state.filename}\nSize: {state.filesize} bytes")
        sock.sendto(struct.pack("!B", PacketType.ACK_META), addr)
        print("📤 Sent ACK_META")

    except Exception as e:
        log_error(f"❌ Failed to decrypt metadata: {e}")
        state.reset()


def handle_data(packet: bytes, addr, state: ReceiverState, sock):
    if not state.connected or state.state != "RECEIVING_FILE":
        log_warn("Unexpected DATA packet. Ignoring.")
        return

    try:
        seq_num = int.from_bytes(packet[1:5], byteorder='big')
        encrypted_chunk = packet[5:]

        # Decrypt nonce + tag + ciphertext
        nonce = encrypted_chunk[:16]
        tag = encrypted_chunk[16:32]
        ciphertext = encrypted_chunk[32:]

        try:
            cipher = AES.new(state.aes_key, AES.MODE_EAX, nonce=nonce)
            chunk = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            log_error(f"❌ Tag mismatch for chunk {seq_num} — possible tampering!")
            return

        if seq_num in state.received_chunks:
            log_info(f"🔁 Duplicate chunk #{seq_num} received. Ignoring.")
        else:
            state.received_chunks[seq_num] = chunk
            log_info(f"✅ Received and stored chunk #{seq_num}")

        ack_packet = struct.pack("!BI", PacketType.ACK, seq_num)
        sock.sendto(ack_packet, addr)

        if len(state.received_chunks) == state.expected_chunks:
            log_success("📦 All file chunks received. Reassembling file...")
            save_chunk_to_file(state)
            show_gui_popup("Transfer Complete", f"File saved to: {state.file_save_path}")
            state.state = "AWAITING_FIN"

    except Exception as e:
        log_error(f"❌ Error handling data packet: {e}")
        state.reset()


def handle_fin(packet: bytes, addr, state: ReceiverState, sock):
    if not state.connected:
        log_warn("❌ Received FIN but no active connection. Ignoring.")
        return

    log_info(f"📴 Received FIN from {addr}. Closing connection.")
    log_info(f"Receiver Idle and open for new connections...")
    sock.sendto(struct.pack("!B", PacketType.ACK_FIN), addr)
    print("📤 Sent ACK_FIN and closed connection")
    show_gui_popup("Connection Closed", "Transfer session has ended.")
    state.reset()
