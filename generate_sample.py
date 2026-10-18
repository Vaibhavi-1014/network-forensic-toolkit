"""Generate a small synthetic PCAP for a safe classroom demonstration."""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
import time

packets = []
base = time.time()

# A small TCP handshake and HTTP-like request/response on a private lab address.
packets.append(Ether()/IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=51514, dport=80, flags="S", seq=1000))
packets.append(Ether()/IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=80, dport=51514, flags="SA", seq=2000, ack=1001))
packets.append(Ether()/IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=51514, dport=80, flags="A", seq=1001, ack=2001))
packets.append(Ether()/IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=51514, dport=80, flags="PA", seq=1001, ack=2001)/Raw(load=b"GET /demo HTTP/1.1\\r\\nHost: lab.local\\r\\n\\r\\n"))
packets.append(Ether()/IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=80, dport=51514, flags="PA", seq=2001, ack=1040)/Raw(load=b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nOK"))

# A DNS query example.
packets.append(Ether()/IP(src="192.168.1.10", dst="192.168.1.53")/UDP(sport=53000, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")))

# Five SYN-only packets to demonstrate the simple review indicator.
for i in range(5):
    packets.append(Ether()/IP(src="192.168.1.99", dst="192.168.1.20")/TCP(sport=40000+i, dport=22+i, flags="S", seq=3000+i))

for i, pkt in enumerate(packets):
    pkt.time = base + i * 0.25

wrpcap("samples/sample_traffic.pcap", packets)
print("Created samples/sample_traffic.pcap")
