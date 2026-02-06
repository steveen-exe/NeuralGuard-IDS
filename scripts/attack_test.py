import sys
import os
import subprocess
import time

def print_menu():
    print("\n=== NeuralGuard Attack Simulator ===")
    print("1. DDoS Attack (TCP Flood)")
    print("2. Port Scan (Fast)")
    print("3. Ping Sweep (Subnet)")
    print("4. Benign Web Traffic")
    print("5. Exit")
    print("====================================")

def run_command(cmd, description):
    print(f"\n[*] Starting {description}...")
    print(f"[*] Command: {cmd}")
    print("[!] Press Ctrl+C to stop (if it's a flood attack)\n")
    try:
        subprocess.run(cmd, shell=True, check=True)
    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

def main():
    target_ip = input("Enter Target IP (e.g., 192.168.56.101): ").strip()
    if not target_ip:
        print("Error: IP required.")
        return

    while True:
        print_menu()
        choice = input("Select an option (1-5): ").strip()

        if choice == '1':
            # DDoS TCP Flood
            # hping3 -S --flood -p 80 <IP>
            cmd = f"sudo hping3 -S --flood -p 80 {target_ip}"
            run_command(cmd, "DDoS TCP Flood")
        
        elif choice == '2':
            # Port Scan
            # nmap -sS -p 1-1000 <IP>
            cmd = f"nmap -sS -p 1-1000 {target_ip}"
            run_command(cmd, "Port Scan")

        elif choice == '3':
            # Ping Sweep
            # nmap -sn <Subnet> (Assume /24 of target IP)
            parts = target_ip.split('.')
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            cmd = f"nmap -sn {subnet}"
            run_command(cmd, "Ping Sweep")

        elif choice == '4':
            # Web Traffic
            cmd = f"curl http://{target_ip}"
            run_command(cmd, "Benign Web Traffic")

        elif choice == '5':
            print("Exiting.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    # Check if we are root for hping3
    if os.geteuid() != 0:
        print("Warning: Some attacks (hping3) require root privileges. You might need to run with sudo.")
    
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting.")
