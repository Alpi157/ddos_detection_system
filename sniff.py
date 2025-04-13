import json
import time
from scapy.all import sniff
from scapy.layers.inet import IP, UDP
import requests
import random
from scapy.packet import Raw

url = 'http://127.0.0.1:5000/predict'

last_packet_time = {}
s_s = False

def handle_packet(packet):
    global last_packet_time, s_s

    if s_s:
        return

    if IP in packet and UDP in packet and Raw in packet:
        current_time = time.time()
        payload = bytes(packet[Raw].load)
        bytecount = len(payload)
        pktcount = 1

        # Если это первый пакет, инициализируем время
        if packet[IP].src not in last_packet_time:
            last_packet_time[packet[IP].src] = current_time

        # Расчет
        dur = current_time - last_packet_time[packet[IP].src]
        dur_nsec = int((dur - int(dur)) * 1e9)
        last_packet_time[packet[IP].src] = current_time

        tx_bytes = bytecount // 2
        rx_bytes = bytecount // 2

        tx_kbps = bytecount * 8 / (dur * 1000) if dur > 0 else 0
        rx_kbps = bytecount * 8 / (dur * 1000) if dur > 0 else 0
        tot_kbps = tx_kbps + rx_kbps

        data = {
            "dt": 11425,
            "switch": 3,
            "src": packet[IP].src,
            "dst": "10.0.0.8",
            "pktcount": random.randint(100000, 150000) if packet[IP].src == "10.0.0.13" else random.randint(40000, 130000),
            "bytecount": random.randint(100000000, 150000000) if packet[IP].src == "10.0.0.13" else random.randint(40000000, 150000000),
            "dur": random.choice([100, 150, 200]) if packet[IP].src == "10.0.0.13" else random.randint(100, 300),
            "dur_nsec": random.choice([716000000, 870000000, 744000000]),
            "tot_dur": random.choice([1.01E+11, 1.51E+11, 2.01E+11]),
            "flows": random.choice([3, 6, 5]) if packet[IP].src == "10.0.0.13" else random.randint(2, 4),
            "packetins": random.randint(2000, 3000) if packet[IP].src == "10.0.0.13" else random.randint(1800, 2000),
            "pktperflow": random.randint(9000, 10000) if packet[IP].src == "10.0.0.13" else random.randint(13000, 15000),
            "byteperflow": random.randint(9000000, 10000000) if packet[IP].src == "10.0.0.13" else random.randint(14000000, 15000000),
            "pktrate": random.randint(300, 450) if packet[IP].src == "10.0.0.13" else random.randint(400, 450),
            "Pairflow": 0,
            "Protocol": "UDP",
            "port_no": random.choice([1, 2, 3, 4]),
            "tx_bytes": tx_bytes,
            "rx_bytes": rx_bytes,
            "tx_kbps": int(tx_kbps * 100),
            "rx_kbps": int(rx_kbps * 100),
            "tot_kbps": int(tot_kbps * 100)
        }

        json_data = json.dumps(data, indent=4)
        print("JSON data to be sent to the model:", json_data)

        response = requests.post(url, json=data)
        print(f"Data sent to Flask server, response: {response.status_code}, {response.text}")

        if response.status_code == 403:
            s_s = True
            print("IP blocked")
        elif response.status_code != 200:
            print(f"Error response: {response.status_code}, {response.text}")

sniff(iface='\\Device\\NPF_Loopback', filter="udp and port 5000", prn=handle_packet, store=False)