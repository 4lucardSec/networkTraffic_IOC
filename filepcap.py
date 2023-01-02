# Import required libraries
import os
import sys
import pcapy
import dpkt

# Set up list of indicators of compromise (IOCs)
IOCs = [
    "1.1.1.1",  # IP address
    "example.com",  # Domain name
    "deadbeef",  # File hash
    "baduser"  # User account
]

# Set up packet capture
pcap_file = "traffic.pcap"
pcap = pcapy.open_offline(pcap_file)

# Set up alert log
alert_log = "alerts.log"

# Process packets
while True:
    # Read packet from pcap file
    header, packet = pcap.next()
    if not header:
        break  # End of pcap file

    # Parse packet
    eth = dpkt.ethernet.Ethernet(packet)
    ip = eth.data
    tcp = ip.data
    if tcp.__class__.__name__ == "TCP":
        payload = tcp.data
    else:
        continue  # Not a TCP packet

    # Check for IOCs in packet payload
    for ioc in IOCs:
        if ioc in payload:
            # Alert!
            with open(alert_log, "a") as f:
                f.write("ALERT: IOC '%s' detected in packet with source IP %s and destination IP %s\n" % (ioc, ip.src, ip.dst))

