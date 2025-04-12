from receiver.packet_handlers import handle_syn, handle_rsa_key, handle_meta, handle_data, handle_fin
from receiver.constants import PacketType

PACKET_TYPES = {
    PacketType.SYN: handle_syn,
    PacketType.RSA_KEY: handle_rsa_key,
    PacketType.META: handle_meta,
    PacketType.DATA: handle_data,
    PacketType.FIN: handle_fin,
}

def dispatch_packet(data, addr, sock, state):
    if not data:
        print("⚠️ Empty packet received.")
        return

    packet_type = data[0]

    handler = PACKET_TYPES.get(packet_type)
    if not handler:
        print(f"⚠️ Unknown packet type: {packet_type}")
        return

    try:
        #FOR DEBUGGING: print(f"[DEBUG] Incoming packet type = {packet_type}, length = {len(data)}")
        handler(data, addr, state, sock)
    except Exception as e:
        print(f"❌ Error in handler for packet type {packet_type}: {e}")

