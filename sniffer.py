from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP

def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "Unknown"

        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[TCP] {ip_src}:{sport} -> {ip_dst}:{dport}")
        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"[UDP] {ip_src}:{sport} -> {ip_dst}:{dport}")
        elif ICMP in packet:
            protocol = "ICMP"
            print(f"[ICMP] {ip_src} -> {ip_dst}")
        else:
            print(f"[{protocol}] {ip_src} -> {ip_dst}")

    elif ARP in packet:
        print(f"[ARP] {packet[ARP].psrc} -> {packet[ARP].pdst}")

def start_sniffing(interface=None):
    print("Starting network sniffer...")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    # You can specify an interface if you want to listen on a specific one, e.g., "eth0"
    interface = "eth0"  # Replace with your network interface, or set to None to sniff on all interfaces
    start_sniffing(interface)
