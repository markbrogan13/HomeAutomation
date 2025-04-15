import threading
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP
import pandas as pd
import sqlite3
from datetime import datetime
import logging, os

'''
    init logger -- want to have better ability for syslog outputs if needbe and 
    safer for a systemctl service
'''
log = logging.getLogger("pcap_logger")
log.setLevel(logging.DEBUG)

# make separate logs for packets over runtime logs
packet_log = logging.getLogger("packet_logger")
packet_log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

file_handler = logging.FileHandler(f'logs/pcap_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
file_handler.setLevel(logging.DEBUG)

# init a new file for the packet logger
file_handler_packets = logging.FileHandler(f'logs/packets_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

log.addHandler(console_handler)
log.addHandler(file_handler)

# adds the custom handlers to the packet logger
packet_log.addHandler(console_handler)
packet_log.addHandler(file_handler_packets)

# raw pcap based off interface, total packets to collect, and output file
def capture_packets(interface, count, output_file):
    packets = sniff(iface=interface, count=count)
    wrpcap(output_file, packets)
    log.info(f'Captured {len(packets)} packets and saved to {output_file}')

# creates a thread to capture the packets, allows main process to be free for more tasks
def background_capture(interface, count, output_file):
    capture_thread = threading.Thread(target=capture_packets, args=(interface, count, output_file))
    log.warning(f'Starting background thread: {capture_thread}')
    capture_thread.start()
    return capture_thread

# inspects and logs the output of the packets, saves to a log file for now
# TODO: add in the ability to save packets to a database
def inspect_packets(input_file, db_filename="net_anon.db"):
    packets = rdpcap(input_file)
    packet_log.info("{:<20} {:<20} {:<10} {:<15} {:<15}".format(
        "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"))
    packet_log.info("-" * 80)  # Separator line

    # Create connection to a SQLite DB
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()

    # Create the packets table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            raw_packet BLOB
        )
    """)

    for packet in packets:
        src_ip = "N/A"
        dst_ip = "N/A"
        protocol_name = "N/A"
        src_port = None
        dst_port = None

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_num = packet[IP].proto
            protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol_num, str(protocol_num))

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        raw_packet = bytes(packet)

        packet_log.info("{:<20} {:<20} {:<10} {:<15} {:<15}".format(
        src_ip, dst_ip, protocol_name, str(src_port), str(dst_port)))

        cursor.execute("""
            INSERT INTO packets (src_ip, dst_ip, protocol, src_port, dst_port, raw_packet)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (src_ip, dst_ip, protocol_name, src_port, dst_port, raw_packet))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    interface = 'en0'
    packet_count = 10000 # arbitrary however this will be a rolling value that I want to operate as a service
    date_time_str = datetime.now().strftime("capture_%Y%m%d_%H%M%S")
    output_file = f'pcaps/{date_time_str}.pcap'

    # Grab the thread we start with background tasks
    background_thread = background_capture(interface, packet_count, output_file)

    log.info('Background task is running')
    packet_log.warning('Starting packet inspection in foreground')

    # TODO: find a better way to do this when pcaps are constant
    for file in os.listdir(f'{os.getcwd()}/pcaps/'):
        log.info(f'Inspecting {file} -- read packet_log file for more info')
        filepath = f'pcaps/{file}'
        inspect_packets(filepath)
        if filepath is not output_file:
            log.warning(f'Removing old file: {file}')
            os.remove(filepath)
    
    # Joins the thread back to the parent task
    background_thread.join()
    inspect_packets(output_file) # inspect the most recent capture
    log.warning(f'Removing current file: {output_file}')
    os.remove(f'{os.getcwd()}/{output_file}')
