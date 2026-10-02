from scapy.all import Packet, IP, UDP
from base_analyzer import PacketAnalyzer

class UDPAnalyzer(PacketAnalyzer):
    def __init__(self, interface: str):
        super().__init__(interface=interface, bpf_filter="udp")

    def format_packet_log(self, packet: Packet):
        # Extract variables directly inside the logger from the packet
        ip_layer = packet[IP]
        udp_layer = packet[UDP]

        ip_src, ip_dst = ip_layer.src, ip_layer.dst
        udp_sport, udp_dport = udp_layer.sport, udp_layer.dport
        udp_chk = udp_layer.chksum
        udp_len = udp_layer.len
        udp_payload = len(udp_layer.payload)
        
        is_overlapping = self.fragment_overlap_detected(packet)

        divider = "-" * 60

        log_output = f"""
        \n{divider}
        \n[*] UDP Packets: 
        \nIP: {ip_src}:{udp_sport} --> {ip_dst}:{udp_dport}
        \nINFO: LEN: {udp_len} | CHK: {udp_chk}
        \nPAYLOAD: {udp_payload} bytes
        """

        if is_overlapping:
            log_output += f"\nWARNING: fragment_overlap"
            
        print(log_output)

    def analyze(self, packet: Packet):     
        if packet.haslayer(IP) and packet.haslayer(UDP):
            self.format_packet_log(packet)
