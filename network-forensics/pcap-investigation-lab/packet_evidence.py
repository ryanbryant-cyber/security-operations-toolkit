import csv
from pathlib import Path

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw


PCAP_FILE = Path("northstar_synthetic_network_capture.pcap")
OUTPUT_DIR = Path("output")
OUTPUT_FILE = OUTPUT_DIR / "packet_evidence.csv"


def get_protocol(packet):
    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"

    return "OTHER"


def get_dns_query(packet):
    if DNS in packet and packet[DNS].qd is not None:
        return packet[DNSQR].qname.decode(
            errors="ignore"
        ).rstrip(".")

    return ""


def get_payload_preview(packet):
    if Raw not in packet:
        return ""

    payload = bytes(packet[Raw].load)

    try:
        preview = payload.decode(
            "utf-8",
            errors="replace"
        )
    except Exception:
        preview = repr(payload)

    return preview[:80]


def extract_packet_data(packet_number, packet):
    if IP not in packet:
        return None

    record = {
        "packet_number": packet_number,
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": get_protocol(packet),
        "source_port": "",
        "destination_port": "",
        "tcp_flags": "",
        "dns_query": get_dns_query(packet),
        "payload_present": "yes" if Raw in packet else "no",
        "payload_length": (
            len(bytes(packet[Raw].load))
            if Raw in packet
            else 0
        ),
        "payload_preview": get_payload_preview(packet)
    }

    if TCP in packet:
        record["source_port"] = packet[TCP].sport
        record["destination_port"] = packet[TCP].dport
        record["tcp_flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        record["source_port"] = packet[UDP].sport
        record["destination_port"] = packet[UDP].dport

    return record


def main():
    packets = rdpcap(str(PCAP_FILE))

    records = []

    for number, packet in enumerate(
        packets,
        start=1
    ):
        record = extract_packet_data(
            number,
            packet
        )

        if record:
            records.append(record)

    OUTPUT_DIR.mkdir(exist_ok=True)

    fieldnames = [
        "packet_number",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "tcp_flags",
        "dns_query",
        "payload_present",
        "payload_length",
        "payload_preview"
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
        f"Extracted {len(records)} packet records."
    )

    print(
        f"Evidence table: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
