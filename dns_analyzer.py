from base_analyzer import PacketAnalyzer
from scapy.all import *


class DNSAnalyzer(PacketAnalyzer):
    def __init__(self, interface: str, allowed_dns_ip:list):
        super().__init__(interface=interface, bpf_filter="udp port 53")
        self.allowed_dns_ip = allowed_dns_ip

    
    def check_dns_leak(self, packet, dst_ip, src_ip):
        # Return True if destination IP is not in approved list
        return dst_ip not in self.allowed_dns_ip

    def get_packet_type(self, packet) -> str:
        # Distinguish between a query and response type
        if packet.haslayer(DNS):
            qr = packet[DNS].qr
            if qr == 0:
                return "QUERY"
            elif qr == 1:
                return "RESPONSE"
        return "UNKNOWN"


    def format_packet_log(self, packet, src_ip, dst_ip):
        divider = "-" * 60  
        packet_type = self.get_packet_type(packet)
        # Safely grab the domain name if a query exists
        domain = "N/A"
        if packet.haslayer(DNS) and packet[DNS].qd and packet[DNS].qd.qname:
            try:
                domain = packet[DNS].qd.qname.decode('UTF-8').rstrip('.')
            except Exception:
                domain = str(packet[DNS].qd.qname)

        # Check for unapproved DNS servers on queries
        leak_warning = ""
        if packet_type == "QUERY" and packet[DNS].qr == 0:
            if self.check_dns_leak(domain, dst_ip, src_ip):
                leak_warning = f"\n[!] DNS LEAK WARNING: {src_ip} queried '{domain}' via unapproved DNS: {dst_ip}"
            else:
                leak_warning = f"\n[+] SECURE: {src_ip} queried '{domain}' via approved DNS: {dst_ip}"

        log_output = f"""
        \n{divider}
        \n[*] DNS Packet Log:
        \nTYPE: {packet_type} | Flow: {src_ip} ---> {dst_ip}
        \nDOMAIN: {domain}
        """

        if leak_warning:
            log_output += f"{leak_warning}"

        print(log_output)
   
    def analyze(self, packet):
        if packet.haslayer(IP) and packet.haslayer(DNS):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            self.format_packet_log(packet, src_ip, dst_ip)

                                
