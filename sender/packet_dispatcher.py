from sender.constants import PacketType
from sender.packet_handlers import handle_ack_syn, handle_rsa_key, handle_ack_aes, handle_ack_meta, handle_ack, handle_ack_fin

PACKET_HANDLERS = {
    PacketType.ACK_SYN: handle_ack_syn,
    PacketType.RSA_KEY: handle_rsa_key,
    PacketType.ACK_AES: handle_ack_aes,
    PacketType.ACK_META: handle_ack_meta,
    PacketType.ACK: handle_ack,
    PacketType.ACK_FIN: handle_ack_fin,
}

def dispatch_packet(packet, state, sock):
    if not packet:
        return

    packet_type = packet[0]
    handler = PACKET_HANDLERS.get(packet_type)

    if handler:
        handler(packet, state, sock)
    else:
        print(f"❓ Unknown packet type: {packet_type}")
