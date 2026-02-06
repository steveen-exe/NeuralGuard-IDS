from scapy.all import sniff, get_if_list, IP, TCP, UDP
import sys
import threading
import time

def check_interfaces():
    print("========================================")
    print("   IDS DIAGNOSTIC TOOL")
    print("========================================")
    
    interfaces = get_if_list()
    print(f"[*] Detected Interfaces: {interfaces}")
    
    target_iface = 'vboxnet0'
    if target_iface not in interfaces:
        print(f"[!] WARNING: '{target_iface}' not found in Scapy interface list.")
        print("    Ensure the interface is up and you have permissions (sudo).")
    else:
        print(f"[*] '{target_iface}' found. Proceeding with capture test...")

    print(f"\n[*] Sniffing on {target_iface} for 10 seconds...")
    print("    Please run your Nmap scan NOW.")
    
    packet_count = 0
    
    def packet_callback(pkt):
        nonlocal packet_count
        packet_count += 1
        if packet_count <= 5: # Limit output
            print(f"    [Captured] {pkt.summary()}")
        elif packet_count % 10 == 0:
             print(f"    [Captured] ... {packet_count} packets total ...")

    try:
        sniff(iface=target_iface, prn=packet_callback, timeout=10, store=0)
    except Exception as e:
        print(f"[!] Sniffing Error: {e}")
        return

    print(f"\n[*] Capture finished. Total packets: {packet_count}")
    if packet_count == 0:
        print("[!] NO PACKETS CAPTURED.")
        print("    Possible causes:")
        print("    1. Interface is wrong/down.")
        print("    2. No traffic generated (did you run nmap?).")
        print("    3. Firewall blocking traffic.")
    else:
        print("[SUCCESS] Traffic detected on vboxnet0. Sniffer configuration is likely correct.")

if __name__ == "__main__":
    check_interfaces()
