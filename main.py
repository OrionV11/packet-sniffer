import sys
import threading
from tcp_analyze import TCPAnalyzer
from dns_analyzer import DNSAnalyzer
from arp_analyze import ARPAnalyzer
from udp_analyze import UDPAnalyzer
from dhcp_analyze import DHCPAnalyzer


local_router = '192.168.1.1'

def main():
    # 1. Define configuration constants
    INTERFACE = 'wlan0'  # Change to your specific interface name
    allowed_dns_ip = ['8.8.8.8', '1.1.1.1', local_router ]
    
    print("[+] Initializing Cyber Security Packet Sniffer...")
    
    try:
        # 2. Initialize the specific analyzer
        analyzers = [
            TCPAnalyzer(interface=INTERFACE),
            DNSAnalyzer(interface=INTERFACE, allowed_dns_ip=allowed_dns_ip),
            DHCPAnalyzer(interface=INTERFACE),
            ARPAnalyzer(interface=INTERFACE),
            UDPAnalyzer(interface=INTERFACE)
        ]

        # 3. Start the process
        threads = []
        for analyzer in analyzers:
            t = threading.Thread(target=analyzer.start_sniffing, daemon=True)
            threads.append(t)
            t.start()
        print("[+] All analyzers running simultaneously. Press Ctrl+C to stop.")
        
        for t in threads:
            t.join()

    except KeyboardInterrupt:
        print("\n[-] Sniffing stopped by user. Exiting safely.")
        sys.exit(0)
    except PermissionError:
        print("\n[!] Error: Root/Administrator privileges are required to sniff packets.")
        sys.exit(1)

if __name__ == "__main__":
    main()

