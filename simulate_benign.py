from scapy.all import send, Raw
from scapy.layers.inet import IP, UDP
import random
import time

def generate_benign_traffic(destination_ip, destination_port):
    while True:
        bytecount = random.randint(40000000, 150000000)
        dur = random.randint(100, 300)
        dur_nsec = random.choice([716000000, 734000000, 744000000])
        port_no = random.choice([1, 2, 3, 4])
        tx_kbps = random.randint(0, 500)
        rx_kbps = random.randint(0, 500)
        tot_kbps = random.randint(0, 1000)
        packet = IP(src="10.0.0.1", dst=destination_ip) / UDP(dport=destination_port, sport=port_no) / Raw(load="X" * (bytecount % 1024))
        send(packet)
        time.sleep(3)

destination_ip = "127.0.0.1"
destination_port = 5000

generate_benign_traffic(destination_ip, destination_port)

