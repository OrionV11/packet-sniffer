from base_analyzer import PacketAnalyzer
from scapy.all import DHCP, Packet


class DHCPAnalyzer(PacketAnalyzer):
    def __init__(self, interface: str):
        super().__init__(interface=interface, bpf_filter="udp and (port 67 or port 68)")

    def analyze(self, packet: Packet):
        if not packet.haslayer(DHCP):
            return
            
        dhcp_pkt = packet[DHCP]
        
        # Extract the DHCP message type safely
        try:
            msg_type = dhcp_pkt.getopt("message-type")
            print(f"[+] DHCP Message Type: {msg_type}")
        except AttributeError:
            print("[!] DHCP Message Type not found in packet.")

        # Print all valid key-value options
        print("[+] DHCP Options:")
        for opt in dhcp_pkt.options:
            if isinstance(opt, tuple):
                opt_name, opt_val = opt
                print(f"    - {opt_name}: {opt_val}")
