from base_analyzer import PacketAnalyzer
from scapy.all import *


class TCPAnalyzer(PacketAnalyzer):
    def __init__(self, interface: str):
        super().__init__(interface=interface, bpf_filter="tcp")
        #Track TCP connection states
        self.TCP_STATES = {}

    #bidirectional key for TCP sessions
    def get_connection_key(self, packet):
        ip = packet[IP]
        tcp = packet[TCP]

        # Sort the endpoints so both directions map to the same key
        endpoint1 = (ip.src, tcp.sport)
        endpoint2 = (ip.dst, tcp.dport)
        sorted_endpoints = sorted([endpoint1, endpoint2])
        return f"{sorted_endpoints[0][0]}:{sorted_endpoints[0][1]}<->{sorted_endpoints[1][0]}:{sorted_endpoints[1][1]}"

    def get_flag_str(self, flags):
        # Convert TCP flags to string format
        flag_str = ""
        if flags & 0x01: flag_str += "F"
        if flags & 0x02: flag_str += "S"
        if flags & 0x04: flag_str += "R"
        if flags & 0x08: flag_str += "P"
        if flags & 0x10: flag_str += "A"
        if flags & 0x20: flag_str += "U"
        return flag_str

    def violate_state_machine(self, packet):
        if IP not in packet or TCP not in packet:
            return False
        
        conn_key = self.get_connection_key(packet)
        tcp = packet[TCP]
        flags = tcp.flags
        flag_str = self.get_flag_str(flags)

        #Allow mid-stream joins by defaulting to ESTABLISHED
        if conn_key not in self.TCP_STATES:
            if flag_str == "S":
                self.TCP_STATES[conn_key] = "SYN_SENT"
            else:
                self.TCP_STATES[conn_key] = "ESTABLISHED"

        current_state = self.TCP_STATES[conn_key]

        # Defined valid states
        valid_transitions = {
                "SYN_SENT": ["SA", "S", "A"], # Expect SYN-ACK
                "ESTABLISHED": ["A", "PA", "F", "FA", "FPA", "R", "RA", "SA"], # Data, ACK, FIN, RST
                "FIN_WAIT_1": ["FA", "A", "PA", "R"], # Expect FIN-ACK or ACK
        }

        allowed = valid_transitions.get(current_state, ["A", "PA", "F", "FA", "R"])
        violation = flag_str not in allowed

        # Update state
        if not violation:
            if "R" in flag_str:
                self.TCP_STATES[conn_key] = "CLOSED"
            elif "S" in flag_str and "A" not in flag_str:
                self.TCP_STATES[conn_key] = "SYN_SENT"
            elif "F" in flag_str:
                self.TCP_STATES[conn_key] = "FIN_WAIT_1"
            else:
                self.TCP_STATES[conn_key] = "ESTABLISHED"
                
        return violation

    def fragment_overlap_detected(self, packet):
        if IP not in packet:
            return False
        ip = packet[IP]

        # Check if packet is fragmented
        if ip.frag == 0 and ip.flags & 0x1 == 0: # No fragments
            return False

        frag_id = ip.id
        frag_offset = ip.frag * 8 # Convert to bytes
        frag_size = len(ip.payload)

        if not hasattr(self, "fragments"):
            self.fragments = {}

        frags = self.fragments

        if frag_id not in frags:
            frags[frag_id] = []

        # Check for overlaps
        new_range = (frag_offset, frag_offset + frag_size)
        for existing_range in frags[frag_id]:
        # Overlapping if ranges interact
            if not (new_range[1] <= existing_range[0] or new_range[0] >= existing_range[1]):
                return True
        self.fragments[frag_id].append(new_range)
        return False


    def detect_malformed_packet(self, packet):
        if IP not in packet or TCP not in packet:
            return {}
        ip = packet[IP]
        tcp = packet[TCP]
        payload_size = len(tcp.payload)
        expected_payload =  ip.len - (ip.ihl * 4) - (tcp.dataofs * 4)

        flag_str = self.get_flag_str(tcp.flags)
        
        # These are direct property checks
        checks = {
            "src_eq_dst": ip.src == ip.dst,  # Always invalid
            "payload_size_mismatch": payload_size != expected_payload,
            "state_machine_violation": self.violate_state_machine(packet),
            "fragment_overlap": self.fragment_overlap_detected(packet),
            "suspicous_rst_incoming": flag_str == "R" and not ip.src.startswith("192.168"),
        }
        
        return checks
    


    def format_packet_log(self, packet):
        # Extract variables directly inside the logger from the packet
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        ip_src, ip_dst = ip_layer.src, ip_layer.dst
        tcp_sport, tcp_dport = tcp_layer.sport, tcp_layer.dport
        tcp_seq, tcp_ack = tcp_layer.seq, tcp_layer.ack
        tcp_flags = tcp_layer.flags
        tcp_payload = len(tcp_layer.payload)
        
        malformed = self.detect_malformed_packet(packet)
        malformed_issues = [ k for k, v in malformed.items() if v]
        packet_time = self.timestamp(packet)

        divider = "-" * 60

        log_output = f"""
        \n{divider}
        \n[*] TCP Packets: 
        \nIP: {ip_src}:{tcp_sport} --> {ip_dst}:{tcp_dport}
        \nINFO: {tcp_seq} --> {tcp_ack} FLAGS: {tcp_flags}
        \nTIMESTAMP: {packet_time}
        \nPAYLOAD: {tcp_payload} bytes
        """

        if malformed_issues:
            log_output += f"\nWARNING: {', '.join(malformed_issues)}"
        print(log_output)


    def analyze(self, packet: Packet):     
        if packet.haslayer(IP) and packet.haslayer(TCP):
            self.format_packet_log(packet)
