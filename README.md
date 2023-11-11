# Network-IDS
Network Intrusion Detection System (IDS) Documentation
The "Network Intrusion Detection System (IDS)" script provides basic intrusion detection capabilities by capturing network packets and searching for predefined attack patterns within these packets. This documentation outlines the functionality, usage, and key aspects of the script.
Purpose:
Intrusion Detection Systems (IDS) are essential security tools that monitor network traffic for suspicious activities and known attack patterns. This script acts as a simple IDS, capturing network packets and identifying potential intrusions based on predefined attack signatures.
Code Structure and Functionality:
    1. Decorators:
        ◦ The script defines a decorator function print_message that prints function names before and after their execution. This decorator provides clarity about the functions being called during program execution.
    2. find_all_networks Function:
        ◦ This function uses the netifaces library to find and list all available network interfaces along with their IP addresses.
    3. Packet Capturing and Storage (packet_capturing Function):
        ◦ The packet_capturing function is responsible for capturing network packets using the sniff function from the scapy library.
        ◦ Captured packets are stored in a list (captured_packets).
        ◦ When the number of captured packets reaches 10, the function saves them to a pcap file named packets.pcap.
    4. Intrusion Detection (intrusion_detection Function):
        ◦ The intrusion_detection function reads the captured packets from packets.pcap using the pyshark library.
        ◦ It searches for predefined attack patterns (such as SQL injection, cross-site scripting, and directory traversal) in the packet data.
        ◦ If a packet matches any of the attack patterns, information about the intrusion is written to a file named network_IDS.txt.
Usage:
    1. Network Interface Selection:
        ◦ Run the script. It will list all available network interfaces and their IP addresses.
        ◦ Enter the name of the network interface you want to use for packet capturing.
    2. Packet Capturing and Intrusion Detection:
        ◦ The script will start capturing network packets on the selected interface.
        ◦ It will capture 10 packets (as specified) and save them to packets.pcap.
        ◦ The captured packets are then analyzed for predefined attack patterns.
        ◦ If any packet matches an attack pattern, information about the intrusion is saved in network_IDS.txt.
Notes:
    • Customization: You can modify the attack_patterns list to include specific attack patterns or signatures relevant to your network's security requirements.
    • Accuracy: The effectiveness of this IDS depends on the accuracy of the attack patterns defined. Ensure that the patterns are well-defined and cover the potential threats specific to your environment.
    • Resource Limitation: This script captures a limited number of packets (10 in this case) for demonstration purposes. In real-world scenarios, you might want to capture a larger number of packets to enhance detection accuracy.
    • Real-Time Monitoring: This script performs intrusion detection on captured packets. For real-time monitoring and immediate response to threats, consider integrating this logic into a continuous network monitoring system.
    • Permissions: Ensure that the script has the necessary permissions to capture network packets on the selected interface. Running the script with administrative privileges may be required on certain operating systems.
    • Logging and Alerts: For production use, consider implementing logging mechanisms and alert notifications to promptly respond to detected intrusions.
    • Security Best Practices: While this script provides a basic IDS functionality, deploying a comprehensive IDS solution with multiple detection methods, anomaly detection, and regular updates is essential for robust network security.
By understanding and customizing the predefined attack patterns, this script can serve as a foundation for building more sophisticated and tailored intrusion detection systems. For production environments, consider using specialized IDS solutions with extensive features and continuous support.
