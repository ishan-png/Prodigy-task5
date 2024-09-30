from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        # Extract IP layer information
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        # Determine protocol type
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = "Other"
        
        
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")
        
        
        if protocol == "TCP" and TCP in packet:
            tcp_payload = packet[TCP].payload
            print(f"TCP Payload: {tcp_payload}")
        elif protocol == "UDP" and UDP in packet:
            udp_payload = packet[UDP].payload
            print(f"UDP Payload: {udp_payload}")
        elif protocol == "ICMP" and ICMP in packet:
            icmp_payload = packet[ICMP].payload
            print(f"ICMP Payload: {icmp_payload}")
        
        print("-" * 50)

def start_sniffer(interface=None):
    print(f"Starting packet capture on {interface if interface else 'default interface'}...")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    # Use None for the default interface, or specify an interface like 'eth0'
    start_sniffer(interface=None)
