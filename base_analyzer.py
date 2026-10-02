from scapy.all import *
from abc import ABC, abstractmethod
from datetime import datetime

class PacketAnalyzer(ABC):
    def __init__(self, interface: str = None, bpf_filter: str = None):
        self.interface = interface
        self.bpf_filter = bpf_filter

   
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

    def start_sniffing(self):
        print(f"[*] Starting packet sniff on {self.interface}")
        if self.bpf_filter:
            print(f"[*] Applying BPF Filter: '{self.bpf_filter}'")
                

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self.packet_callback, 
            store=False
        )


    def packet_callback(self, packet: Packet):
        if packet:
            self.analyze(packet)

    def timestamp(self, packet:Packet) -> str:
        dt_obj = datetime.fromtimestamp(float(packet.time))
        timestamp = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
        return timestamp


    @abstractmethod
    def analyze(self, packet: Packet):
        """
            Blueprint method. Subclasses MUST implement this to handle
            pre-parsed Scapy Packet objects.
        """
        pass

