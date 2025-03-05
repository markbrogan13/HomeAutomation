"""
    More sophisticated way of WoL for home machines and automation stuffers
"""

import wakeonlan as wol
import logging
import yaml
import subprocess
import argparse
import socket
import os, sys, time

# base dataset for the yaml file
NODE_DATA = None

# init parser
parser = argparse.ArgumentParser(description="Wake on LAN with sophisticated response and dynamic checks")

# add args for parser
parser.add_argument("-n", "--hostname", type=str, help="Hostname of the device you want to wake", required=True)
parser.add_argument("-i", "--nic-type", type=str, help="Interface type, ETH | WIFI", default="ETH")

# init logger
log = logging.getLogger("wol_logger")
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

file_handler = logging.FileHandler("wol.log")
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

log.addHandler(console_handler)
log.addHandler(file_handler)

# Sends a subprocess ping to see if the host is already alive
def check_on_state(ip_addr, packets=1):
    log.info(f"starting ping on {ip_addr}")
    state = subprocess.run(["ping", "-c", str(packets), ip_addr], capture_output=True, text=True)
    result = state.stdout

    # returns a logical false, noting the device is offline. Otherwise logical true for anything less than 100% loss
    if "100% packet loss" in result:
        log.warning("Host is down")
        return False
    else:
        log.info("Host is alive")
        return True

if __name__ == "__main__":
    # Load the yaml file into the dataset variable
    with open("dataset.yml", "r") as inv:
        NODE_DATA = yaml.safe_load(inv)

    """
        Running this should take in flags for:
        -n, --hostname : hostname of the device
        -i, --nic-type : device NIC [ETH | WIFI]
    """
    args = parser.parse_args() # parses into argument subtypes

    if args.nic_type == "ETH": # Ethernet NIC type (Default)
        return_val = check_on_state(NODE_DATA["NODES"][args.hostname]["HOST_IP_ETH"])
        host_ip = NODE_DATA["NODES"][args.hostname]["HOST_IP_ETH"] # set the ETH host IP from the yml in local var
    elif args.nic_type == "WIFI": # Wireless devices (only select machines)
        return_val = check_on_state(NODE_DATA["NODES"][args.hostname]["HOST_IP_WIFI"])
        host_ip = NODE_DATA["NODES"][args.hostname]["HOST_IP_WIFI"] # set WIFI host IP from the yml in local var
    else:
        log.error("NIC type not supported") # Log the failures
        sys.exit(-1)

    """
        Obtain the server IP address, split into individual octets
        splits the host IP into octets
    """
    server_ip = socket.gethostbyname(socket.gethostname())
    server_ip_octets = server_ip.split('.')
    host_ip_octets = host_ip.split('.')

    # go through first three octets and check for mis-match (BUG: /24-/32 networks ONLY)
    for i in range(0, len(server_ip_octets) - 1):
        if not server_ip_octets[i] == host_ip_octets[i]:
            log.error(f'Subnet/VLAN mismatch -- packet will not sent across subnets:')
            log.error(f'Server IP: {server_ip}, Host IP: {host_ip}')
            sys.exit(-1)
    
    # if the process does not exit, flip the boolean and check the NIC type once more, then create and send the magic packet
    if not return_val and args.nic_type == "ETH":
        log.info(f'Creating magic packet for {NODE_DATA["NODES"][args.hostname]["HOST_MAC_ETH"]}')
        wol.create_magic_packet(NODE_DATA["NODES"][args.hostname]["HOST_MAC_ETH"])
        log.warning("Wake on LAN packet sent. Not yet confirmed as completed")
    elif not return_val and args.nic_type == "WIFI":
        log.info(f'Creating magic packet for {NODE_DATA["NODES"][args.hostname]["HOST_MAC_ETH"]}')
        wol.create_magic_packet(NODE_DATA["NODES"][args.hostname]["HOST_MAC_WIFI"])
        log.warning("Wake on LAN packet sent. Not yet confirmed as completed")
    else:
        log.error(f'Process failed to make a WoL packet:')
        log.critical('Exiting -- host already online') # Task failed successfully (client is on)
        sys.exit(-1)

    # wait 20 seconds for a boot
    log.debug('Sleep script for 20 seconds -- allows time to boot on the current Host OS')
    time.sleep(20)

    # Sanity check -- sends 20 packets to verify is the host is online or not
    if args.nic_type == "ETH":
        log.info(f"pinging host ... {host_ip} for 20 packets")
        return_val_post_wol = check_on_state(host_ip, 20)
    elif args.nic_type == "WIFI":
        log.info(f"pinging host ... {host_ip} for 20 packets")
        return_val_post_wol = check_on_state(host_ip, 20)
        
# TODO: add in helper functions and add in continuation for other tasks based on device
