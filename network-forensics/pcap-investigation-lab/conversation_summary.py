import csv
from collections import defaultdict
from pathlib import Path

from scapy.all import rdpcap, IP, TCP, Raw


PCAP_FILE = Path("northstar_synthetic_network_capture.pcap")
OUTPUT_DIR = Path("output")
OUTPUT_FILE = OUTPUT_DIR / "tcp_conversation_summary.csv"


def conversation_key(packet):
    """Create one key for both directions of a TCP conversation."""
    endpoint_a = (
        packet[IP].src,
        packet[TCP].sport
    )

    endpoint_b = (
        packet[IP].dst,
        packet[TCP].dport
    )

    return tuple(sorted([endpoint_a, endpoint_b]))


def main():
    packets = rdpcap(str(PCAP_FILE))

    conversations = defaultdict(list)

    for packet_number, packet in enumerate(
        packets,
        start=1
    ):
        if IP not in packet or TCP not in packet:
            continue

        conversations[conversation_key(packet)].append(
            (packet_number, packet)
        )

    records = []

    for conversation_number, events in enumerate(
        conversations.values(),
        start=1
    ):
        first_number, first_packet = events[0]

        initiator_ip = first_packet[IP].src
        initiator_port = first_packet[TCP].sport
        responder_ip = first_packet[IP].dst
        responder_port = first_packet[TCP].dport

        syn_seen = False
        syn_ack_seen = False
        ack_seen = False
        payload_packets = 0
        payload_bytes = 0

        packet_numbers = []

        for packet_number, packet in events:
            packet_numbers.append(packet_number)

            flags = str(packet[TCP].flags)

            if flags == "S":
                syn_seen = True

            elif flags == "SA":
                syn_ack_seen = True

            elif "A" in flags:
                ack_seen = True

            if Raw in packet:
                payload_packets += 1
                payload_bytes += len(
                    bytes(packet[Raw].load)
                )

        handshake_complete = (
            syn_seen
            and syn_ack_seen
            and ack_seen
        )

        records.append(
            {
                "conversation": conversation_number,
                "initiator_ip": initiator_ip,
                "initiator_port": initiator_port,
                "responder_ip": responder_ip,
                "responder_port": responder_port,
                "packet_numbers": ",".join(
                    str(number)
                    for number in packet_numbers
                ),
                "packet_count": len(events),
                "syn_seen": "yes" if syn_seen else "no",
                "syn_ack_seen": "yes" if syn_ack_seen else "no",
                "ack_seen": "yes" if ack_seen else "no",
                "handshake_complete": (
                    "yes"
                    if handshake_complete
                    else "no"
                ),
                "payload_packets": payload_packets,
                "payload_bytes": payload_bytes
            }
        )

    OUTPUT_DIR.mkdir(exist_ok=True)

    fieldnames = [
        "conversation",
        "initiator_ip",
        "initiator_port",
        "responder_ip",
        "responder_port",
        "packet_numbers",
        "packet_count",
        "syn_seen",
        "syn_ack_seen",
        "ack_seen",
        "handshake_complete",
        "payload_packets",
        "payload_bytes"
    ]

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
        newline=""
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(records)

    print(
        f"TCP conversations: {len(records)}"
    )

    print(
        f"Conversation summary: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
