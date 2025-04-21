import sqlite3
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
import logging, os

'''
    init logger -- want to have better ability for syslog outputs if needbe and 
    safer for a systemctl service
'''
log = logging.getLogger("detection_logger")
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

file_handler = logging.FileHandler(f'logs/detection_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

log.addHandler(console_handler)
log.addHandler(file_handler)

def import_packet_database(db_filename="net_anon.db"):
    conn = sqlite3.connect(db_filename)
    query = "SELECT src_ip, dst_ip, protocol, CAST(src_port AS INTEGER) AS src_port, CAST(dst_port AS INTEGER) AS dst_port FROM packets"  # Exclude raw packet for now
    
    pd.set_option('display.float_format', '{:.0f}'.format) # weird bug where ports were having a decimal added
    
    df = pd.read_sql_query(query, conn)
    log.info(f"Packet data  loaded successfully from SQLite db: {db_filename}")
    conn.close()

    return df

def create_features(df):
    log.info("Starting feature engineering -- This may take a while")
    # 1. Protocol encoding
    protocol_encoded = pd.get_dummies(df['protocol'], prefix='protocol')
    df = pd.concat([df, protocol_encoded], axis=1)
    df.drop('protocol', axis=1, inplace=True)

    # 2. Combined Port Feature
    df['port_pair'] = df['src_port'].astype(str) + '-' + df['dst_port'].astype(str)
    port_pair_encoder = LabelEncoder()
    df['port_pair_encoded'] = port_pair_encoder.fit_transform(df['port_pair'])
    df.drop('port_pair', axis=1, inplace=True)

    # 3. Combined IP Address Feature
    df['ip_pair'] = df['src_ip'].astype(str) + '-' + df['dst_ip'].astype(str)
    ip_pair_encoder = LabelEncoder()
    df['ip_pair_encoded'] = ip_pair_encoder.fit_transform(df['ip_pair'])
    df.drop('ip_pair', axis=1, inplace=True)

    # 4. Connection Frequency Features
    # Combine source IP, destination IP, and destination port to define a "connection"
    df['connection'] = df['src_ip'].astype(str) + '-' + df['dst_ip'].astype(str) + ':' + df['dst_port'].astype(str)

    # Calculate the frequency of each connection
    connection_counts = df['connection'].value_counts().to_dict()
    df['connection_frequency'] = df['connection'].map(connection_counts)
    df.drop('connection', axis=1, inplace=True)

    # Drop the original IP and port columns as we've created combined/encoded versions
    df.drop(['src_ip', 'dst_ip', 'src_port', 'dst_port'], axis=1, inplace=True, errors='ignore')

    log.info(f"Features engineered successfully")
    return df

if __name__ == "__main__":
    packet_df = import_packet_database()
    if packet_df is not None:
        feature_df = create_features(packet_df.copy())
        print(feature_df.head())