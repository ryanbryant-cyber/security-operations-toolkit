from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap


packets = []

# Normal DNS query
packets.append(
    IP(src="10.10.20.17", dst="10.10.10.53")
    / UDP(sport=53001, dport=53)
    / DNS(
        rd=1,
        qd=DNSQR(qname="portal.northstar.example")
    )
)

# Normal HTTPS-style TCP handshake to approved service
packets.extend(
    [
        IP(src="10.10.20.17", dst="203.0.113.10")
        / TCP(sport=51000, dport=443, flags="S", seq=1000),

        IP(src="203.0.113.10", dst="10.10.20.17")
        / TCP(sport=443, dport=51000, flags="SA", seq=2000, ack=1001),

        IP(src="10.10.20.17", dst="203.0.113.10")
        / TCP(sport=51000, dport=443, flags="A", seq=1001, ack=2001),
    ]
)

# Repeated connection attempts to SSH on internal Finance server
for source_port in [52001, 52002, 52003, 52004]:
    packets.append(
        IP(src="10.10.20.17", dst="10.10.20.40")
        / TCP(
            sport=source_port,
            dport=22,
            flags="S",
            seq=3000 + source_port
        )
    )

# Suspicious DNS query
packets.append(
    IP(src="10.10.20.17", dst="10.10.10.53")
    / UDP(sport=53020, dport=53)
    / DNS(
        rd=1,
        qd=DNSQR(qname="sync-update.example")
    )
)

# Suspicious outbound HTTPS connection
packets.extend(
    [
        IP(src="10.10.20.17", dst="203.0.113.77")
        / TCP(sport=52361, dport=443, flags="S", seq=4000),

        IP(src="203.0.113.77", dst="10.10.20.17")
        / TCP(sport=443, dport=52361, flags="SA", seq=5000, ack=4001),

        IP(src="10.10.20.17", dst="203.0.113.77")
        / TCP(sport=52361, dport=443, flags="A", seq=4001, ack=5001),

        IP(src="10.10.20.17", dst="203.0.113.77")
        / TCP(sport=52361, dport=443, flags="PA", seq=4001, ack=5001)
        / Raw(load=b"synthetic-training-data"),
    ]
)

# Unusual outbound connection to non-standard port
packets.extend(
    [
        IP(src="10.10.20.17", dst="203.0.113.88")
        / TCP(sport=52488, dport=8443, flags="S", seq=6000),

        IP(src="203.0.113.88", dst="10.10.20.17")
        / TCP(sport=8443, dport=52488, flags="SA", seq=7000, ack=6001),

        IP(src="10.10.20.17", dst="203.0.113.88")
        / TCP(sport=52488, dport=8443, flags="A", seq=6001, ack=7001),
    ]
)

# Normal internal application traffic
packets.extend(
    [
        IP(src="10.10.20.17", dst="10.10.20.40")
        / TCP(sport=52550, dport=443, flags="S", seq=8000),

        IP(src="10.10.20.40", dst="10.10.20.17")
        / TCP(sport=443, dport=52550, flags="SA", seq=9000, ack=8001),

        IP(src="10.10.20.17", dst="10.10.20.40")
        / TCP(sport=52550, dport=443, flags="A", seq=8001, ack=9001),
    ]
)

wrpcap("northstar_synthetic_network_capture.pcap", packets)

print(
    f"Created northstar_synthetic_network_capture.pcap "
    f"with {len(packets)} packets."
)
