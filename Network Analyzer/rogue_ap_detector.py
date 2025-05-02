from scapy.all import ARP, Ether, srp
packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")  # Replace with your local subnet
ans, _ = srp(packet, timeout=2)
for sent, received in ans:
    print(received.psrc, received.hwsrc)
