import sys
import logging
import time
import threading
from collections import defaultdict, deque
import pandas as pd
import matplotlib

matplotlib.use('TkAgg')  # Alternative: 'Qt5Agg' if using Qt
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, IP, TCP, UDP, ICMP

# -------------------- Logging Setup -------------------- #
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# -------------------- Data Structures -------------------- #
protocol_counts = defaultdict(int)
bandwidth_usage = defaultdict(lambda: {"sent": 0, "received": 0})
packet_timestamps = deque(maxlen=1000)  # Track last 1000 packets for inter-arrival times
traffic_data = []
lock = threading.Lock()


def protocol_name(number):
    """ Convert protocol number to human-readable name """
    protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 132: 'SCTP', 2: 'IGMP', 47: 'GRE'}
    return protocol_dict.get(number, f"Unknown({number})")


def packet_callback(packet):
    """ Extracts features for ML dataset """
    if IP in packet:
        timestamp = time.time()
        src = packet[IP].src
        dst = packet[IP].dst
        proto = protocol_name(packet[IP].proto)
        size = len(packet)
        inter_arrival_time = timestamp - packet_timestamps[-1] if packet_timestamps else 0
        packet_timestamps.append(timestamp)

        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)

        tcp_flags = None
        if TCP in packet:
            flags = packet[TCP].flags
            tcp_flags = f"SYN={flags & 0x02}, ACK={flags & 0x10}, FIN={flags & 0x01}"

        with lock:
            protocol_counts[proto] += 1
            traffic_data.append([timestamp, proto, src, dst, src_port, dst_port, size, inter_arrival_time, tcp_flags])
            bandwidth_usage[src]["sent"] += size
            bandwidth_usage[dst]["received"] += size

        logger.info(
            f"Packet: {proto} | {src}:{src_port} → {dst}:{dst_port} | Size: {size} bytes | Inter-Arrival: {inter_arrival_time:.6f}s")


def save_to_csv():
    """ Periodically saves collected data to CSV for ML training """
    while True:
        time.sleep(10)
        with lock:
            df = pd.DataFrame(traffic_data, columns=[
                "Timestamp", "Protocol", "Source", "Destination",
                "Source Port", "Destination Port", "Size",
                "Inter-Arrival Time", "TCP Flags"
            ])
            df.to_csv("network_traffic_ml.csv", index=False)
            traffic_data.clear()

            bw_df = pd.DataFrame.from_dict(bandwidth_usage, orient="index")
            bw_df.reset_index(inplace=True)
            bw_df.columns = ["IP Address", "Sent (Bytes)", "Received (Bytes)"]
            bw_df.to_csv("bandwidth_usage.csv", index=False)


threading.Thread(target=save_to_csv, daemon=True).start()


# -------------------- Live Visualization -------------------- #
def update_chart(frame):
    plt.clf()
    with lock:
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())
        ips = list(bandwidth_usage.keys())
        sent_bytes = [bandwidth_usage[ip]["sent"] for ip in ips]
        received_bytes = [bandwidth_usage[ip]["received"] for ip in ips]

    plt.subplot(2, 1, 1)
    plt.bar(protocols, counts, color=['#3674B5', '#DE3163', '#EFB036', '#16C47F'])
    plt.title("Live Network Traffic (Bar)")
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")

    plt.subplot(2, 1, 2)
    plt.bar(ips, sent_bytes, label="Sent", color='blue', alpha=0.6)
    plt.bar(ips, received_bytes, label="Received", color='red', alpha=0.6)
    plt.xticks(rotation=45, ha="right")
    plt.title("Bandwidth Usage per IP")
    plt.xlabel("IP Address")
    plt.ylabel("Bytes Transferred")
    plt.legend()
    plt.tight_layout()


def start_sniffing():
    sniff(prn=packet_callback, store=False)


# -------------------- Main Function -------------------- #
def main(mode, pcap_file=None):
    if mode == "offline":
        if not pcap_file:
            logger.error("Please provide a PCAP file for offline analysis.")
            sys.exit(1)
    elif mode == "live":
        threading.Thread(target=start_sniffing, daemon=True).start()
        ani = FuncAnimation(plt.gcf(), update_chart, interval=1000, cache_frame_data=False)
        plt.show()
    else:
        logger.error("Invalid mode! Use 'offline' or 'live'.")
        sys.exit(1)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "live"
    pcap_file = sys.argv[2] if len(sys.argv) > 2 else None
    main(mode, pcap_file)