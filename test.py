import sys
import logging
from scapy.all import *
import pandas as pd
from tabulate import tabulate
from tqdm import tqdm

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def read_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        sys.exit(1)
    return packets


def extract_packet_data(packets):
    packet_data = []
    sttp_data = []

    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)

            if TCP in packet or UDP in packet:
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                if dst_port in [102, 61850, 2404]:  # IEC 61850 MMS (102), GOOSE/SV (61850), IEC 60870-5-104 (2404)
                    sttp_data.append(
                        {"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size, "dst_port": dst_port})
                else:
                    packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size})
            else:
                packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size})

    return pd.DataFrame(packet_data), pd.DataFrame(sttp_data)


def protocol_name(number):
    protocol_dict = {1: 'SCTP', 6: 'TCP', 17: 'UDP'}
    return protocol_dict.get(number, f"Unknown({number})")


def analyze_packet_data(df, sttp_df):
    total_bandwidth = df["size"].sum()
    protocol_counts = df["protocol"].value_counts(normalize=True) * 100

    if isinstance(protocol_counts, pd.Series):
        protocol_counts = protocol_counts.reset_index()
        protocol_counts.columns = ["Protocol", "Percentage"]
        protocol_counts["Protocol"] = protocol_counts["Protocol"].map(protocol_name)
    else:
        protocol_counts = pd.DataFrame([["Unknown", protocol_counts]], columns=["Protocol", "Percentage"])

    ip_communication = df.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False)
    ip_communication_percentage = ip_communication / ip_communication.sum() * 100
    ip_communication_table = pd.concat([ip_communication, ip_communication_percentage], axis=1).reset_index()

    # Ensure sttp_df is not empty before accessing 'size'
    if not sttp_df.empty and "size" in sttp_df.columns:
        sttp_bandwidth = sttp_df["size"].sum()
        sttp_summary = sttp_df.groupby("dst_port").size().reset_index(name="count")
    else:
        sttp_bandwidth = 0
        sttp_summary = pd.DataFrame(columns=["dst_port", "count"])  # Empty DataFrame to prevent errors

    # Port scan detection
    port_scan_summary = detect_port_scan(df)

    return total_bandwidth, protocol_counts, ip_communication_table, sttp_bandwidth, sttp_summary, port_scan_summary


def detect_port_scan(df):
    # Thresholds for port scanning
    threshold = 20
    port_scan_data = []

    # Group by destination port and count unique source IPs targeting that port
    port_scan_counts = df.groupby("dst_ip")["src_ip"].nunique()

    # Detect potential port scans by checking if the number of unique sources is above the threshold
    for port, count in port_scan_counts.items():
        if count >= threshold:
            port_scan_data.append({"Port": port, "Unique Source IPs": count})

    return pd.DataFrame(port_scan_data)


def print_results(total_bandwidth, protocol_counts, ip_communication_table, sttp_bandwidth, sttp_summary, port_scan_summary):
    logger.info(f"Total bandwidth used: {total_bandwidth / 1e6:.2f} Mbps")
    logger.info("\nProtocol Distribution:\n")
    logger.info(tabulate(protocol_counts, headers=["Protocol", "Percentage"], tablefmt="grid"))
    logger.info("\nTop IP Address Communications:\n")
    logger.info(tabulate(ip_communication_table, headers=["Source IP", "Destination IP", "Count", "Percentage"],
                         tablefmt="grid", floatfmt=".2f"))

    if not sttp_summary.empty:
        logger.info(f"\nTotal STTP Bandwidth Used: {sttp_bandwidth / 1e6:.2f} Mbps")
        logger.info("\nSTTP Packet Distribution by Port:\n")
        logger.info(tabulate(sttp_summary, headers=["Destination Port", "Packet Count"], tablefmt="grid"))

    if not port_scan_summary.empty:
        logger.info("\nDetected Port Scanning Activities:\n")
        logger.info(tabulate(port_scan_summary, headers=["Port", "Unique Source IPs"], tablefmt="grid"))
    else:
        logger.info("\nNo Port Scanning Activities Detected.")


def main(pcap_file):
    packets = read_pcap(pcap_file)
    df, sttp_df = extract_packet_data(packets)
    total_bandwidth, protocol_counts, ip_communication_table, sttp_bandwidth, sttp_summary, port_scan_summary = analyze_packet_data(df,
                                                                                                                 sttp_df)
    print_results(total_bandwidth, protocol_counts, ip_communication_table, sttp_bandwidth, sttp_summary, port_scan_summary)


if __name__ == "__main__":
    pcap_file = "/Users/hassanmansuri/PycharmProjects/Major/Large2.pcapng"  # Set your PCAP file path here
    main(pcap_file)
