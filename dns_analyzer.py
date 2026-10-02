from base_analyzer import PacketAnalyzer
from scapy.all import *


class DNSAnalyzer(PacketAnalyzer):
    def __init__(self, interface: str, allowed_dns_ip:list):
        super().__init__(interface=interface, bpf_filter="udp port 53")
        self.allowed_dns_ip = allowed_dns_ip

    def dns_leak(self, packet, dst_ip, src_ip):
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            if packet[DNS].qd:
                domain = packet[DNS].qd.qname.decode('UTF-8')
            if dst_ip not in self.allowed_dns_ip:
                    print(f" LEAK! {src_ip} requested '{domain}' via unapproved DNS: {dst_ip}")
            else:
                print(f" SECURE {src_ip} requested '{domain}' via {dst_ip}")


    def get_packet_type(self, packet) -> str:
        if packet.haslayer(DNS):
            qr = packet[DNS].qr
            if qr == 0:
                return "QUERY"
            elif qr == 1:
                return "RESPONSE"
        return "UNKNOWN"


    def format_packet_log(self, packet_type, src_ip, dst_ip, packet):
        # A clean, single template that adapts based on the live packet type
        divider = "-" * 60
        
        # Safely grab the domain name if a query exists
        domain = "N/A"
        if packet.haslayer(DNS) and packet[DNS].qd:
            domain = packet[DNS].qd.qname.decode('UTF-8')

        log_output = f"""
        \n{divider}
        \n[*] DNS Packet Log:
        \nTYPE: {packet_type} | Flow: {src_ip} ---> {dst_ip}
        \nDOMAIN: {domain}
        """
        print(log_output)
   
    def analyze(self, packet):
        if packet.haslayer(IP) and packet.haslayer(DNS):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            dns_pkt = packet[DNS]
            dns_qd = dns_pkt.qd
            dns_qr = dns_pkt.qr


            dns_id = dns_pkt.id
            dns_an = dns_pkt.an
            dns_ns = dns_pkt.ns
            dns_ar = dns_pkt.ar


            dns_leak = self.dns_leak(packet, dst_ip, src_ip)
            packet_type = self.get_packet_type(packet)
            self.format_packet_log(packet_type, src_ip, dst_ip, packet)

                                
