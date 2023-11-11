# Network Intrusion Detection System (IDS)
import re
import pyshark
from scapy.all import sniff, wrpcap
import netifaces

# Decorator 
def print_message(func):
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__}...")
        result = func(*args, **kwargs)
        print(f"{func.__name__} completed.")
        return result
    return wrapper

# Function for finding all networks
@print_message
def find_all_networks():
    interfaces = netifaces.interfaces()  # Get a list of available network interfaces

    interfaces_list = []

    for interface in interfaces:
        interface_info = {
            'name': interface,
            'ip': netifaces.ifaddresses(interface).get(netifaces.AF_INET, [{'addr': 'No IP'}])[0]['addr'],
        }
        interfaces_list.append(interface_info)

    return interfaces_list

# Capturing packets and saving them to a file
@print_message
def packet_capturing(packet):
    captured_packets.append(packet)  # Add the captured packet to the list
    try:
        if len(captured_packets) == 10:
            wrpcap("packets.pcap", captured_packets)  # Save the captured packets to a pcap file
            print("Packets captured and saved successfully.")

    except Exception as e:
        print(f"Error occurred while printing all functions: {str(e)}")

# Detecting intrusion
@print_message
def intrusion_detection(attack_patterns):
    # Opening packets
    capture = pyshark.FileCapture("packets.pcap")

    for packet in capture:
        packet_data = str(packet)  # Convert the packet object to a string
        # Convert packet data to lowercase for case-insensitive matching
        packet_data = packet_data.lower()
        # Check if packet matches any of the attack patterns
        for pattern in attack_patterns:
            if re.search(pattern, packet_data):
                with open ("network_IDS.txt", 'w') as file:
                    file.write(f"Intrusion Found in packet: {packet}")
    print("Network intrusion completed")

if __name__ == "__main__":
    networks = find_all_networks()

    # Checking availability of the networks
    try:
        if len(networks) > 0:
            print("Networks Found :)")
            for network in networks:
                print(network)

            # Which interface user wants to use from the available interfaces
            select_iface = input("Enter the interface: ")
            select_filtering = input("Enter the filter (tcp/udp): ")

            # Initialize the list to store captured packets
            captured_packets = []

            # Network sniff
            sniff(iface=select_iface, filter=select_filtering, prn=packet_capturing, count=10)

    except:
        print("No Network Found :(")

    # Define a list of patterns for known attack signatures
    attack_patterns = [
        r'sql\s*injection',
        r'cross\s*site\s*scripting',
        r'directory\s*traversal',
    ]

    intrusion_detection(attack_patterns)
