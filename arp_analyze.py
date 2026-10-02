from base_analyzer import PacketAnalyzer
from scapy.all import Packet, ARP

class ARPAnalyzer(PacketAnalyzer):
    def __init__(self, interface: str):
        super().__init__(interface=interface, bpf_filter=None)
        # Keep track of IP -> MAC associations in memory
        self.ip_mac_table = {}

    def analyze(self, packet: Packet):
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
           
            #Variables
            arp_type = arp_layer.ptype
            mac_len = arp_layer.hwlen
            ip_len = arp_layer.plen

            # Extract standard fields
            sender_mac = arp_layer.hwsrc
            dst_mac = arp_layer.hwdst
            sender_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst
            operation = arp_layer.op # 1 = Request, 2 = Reply
            
            # Check for ARP Spoofing / Poisoning
            if sender_ip in self.ip_mac_table:
                old_mac = self.ip_mac_table[sender_ip]
                
                # If the IP address is now tied to a different MAC address, trigger alert
                if old_mac.lower() != sender_mac.lower():
                    print(f"\n[ CRITICAL ALERT] Potential ARP Spoofing Detected!")
                    print(f"    IP Address: {sender_ip}")
                    print(f"    Original MAC: {old_mac}")
                    print(f"    New Suspect MAC: {sender_mac}")
                    print(f"    Action: Host may be trying to intercept network traffic!\n")
            else:
                # If it's a new IP, cache the mapping
                self.ip_mac_table[sender_ip] = sender_mac

            # Optional: Log standard traffic for debugging
            op_text = "REQUEST" if operation == 1 else "REPLY"
            print(f"[*][ARP {op_text}] {sender_ip} is at {sender_mac}")

