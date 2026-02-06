import sys
import time
import logging
import joblib
import pandas as pd
import numpy as np
import requests
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ==============================================================================
# 1. CONFIGURATION
# ==============================================================================
CONFIG = {
    "INTERFACE": "vboxnet0",          # Network Interface
    "MODEL_PATH": "../models/ids_ensemble_final.pkl",
    "API_URL": "http://localhost:5000/api/alert",
    
    "CONFIDENCE_THRESHOLD": 0.70,     # Alert confidence
    "DOS_RATE_THRESHOLD": 100.0,      # Pkts/sec to confirm DDoS (increased for stability)
    "SCAN_PORT_THRESHOLD": 5,         # Unique ports to confirm PortScan
    "SCAN_IP_THRESHOLD": 5,           # Unique IPs to confirm NetScan

    # IGNORED IPs (Noise Filter)
    "IGNORED_IPS": [
        "224.0.0.22", "239.255.255.250", "255.255.255.255", 
        "127.0.0.1", "0.0.0.0"
    ],

    # MANUAL MAPPING (Update based on your model's integer output)
    "MANUAL_MAPPING": {
        0: "Benign",
        1: "DDoS-TCP",
        2: "DDoS-UDP",
        3: "PortScan",
        4: "Mirai-Botnet",
        5: "DDoS-ICMP"
    }
}

EXPECTED_FEATURES = [
     'flow_duration', 'header_length', 'protocol_type', 'duration', 'rate', 'srate', 'drate',
     'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
     'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count',
     'rst_count', 'http', 'https', 'dns', 'telnet', 'smtp', 'ssh', 'irc', 'tcp', 'udp', 'dhcp',
     'arp', 'icmp', 'ipv', 'llc', 'tot_sum', 'min', 'max', 'avg', 'std', 'tot_size', 'iat',
     'number', 'radius', 'covariance', 'variance', 'weight', 'magnitude'
]

# ==============================================================================
# 2. STATE TRACKING (Fixed for Web Traffic)
# ==============================================================================
logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s', level=logging.INFO)
logger = logging.getLogger("IDS_Core")

class FlowTracker:
    def __init__(self):
        self.flows = {} 
        self.last_cleanup = time.time()

    def update(self, src_ip, dst_ip, packet):
        now = time.time()
        
        # Cleanup every 10s
        if now - self.last_cleanup > 10:
            self.flows = {k: v for k, v in self.flows.items() if (now - v['last_seen']) < 30}
            self.last_cleanup = now

        if src_ip not in self.flows:
            self.flows[src_ip] = {
                'start': now, 'count': 0, 'syns': 0, 'last_seen': now,
                'dest_ips': set(),
                'dest_ports': set()
            }
        
        f = self.flows[src_ip]
        f['count'] += 1
        f['last_seen'] = now
        f['dest_ips'].add(dst_ip)
        
        # --- THE FIX FOR WEB TRAFFIC ---
        # Only track Destination Ports if the Source Port is NOT a web server (80/443).
        # This prevents Server Responses (Source 80 -> Client 54321, 54322) from looking like a scan.
        is_server_response = False
        if packet.haslayer(TCP):
            if packet[TCP].sport in [80, 443, 8080]: # It's a server replying
                is_server_response = True
            
            if not is_server_response:
                f['dest_ports'].add(packet[TCP].dport)
            
            if 'S' in packet[TCP].flags: 
                f['syns'] += 1

        elif packet.haslayer(UDP):
            if packet[UDP].sport in [53, 443]: # DNS/QUIC responses
                is_server_response = True
            
            if not is_server_response:
                f['dest_ports'].add(packet[UDP].dport)

        # Stats Calc
        duration = now - f['start']
        safe_dur = duration if duration > 0.001 else 0.001
        rate = f['count'] / safe_dur
        
        return duration, rate, f['syns'], len(f['dest_ips']), len(f['dest_ports'])

# ==============================================================================
# 3. INTELLIGENCE ENGINE
# ==============================================================================
class IDSEngine:
    def __init__(self):
        self.tracker = FlowTracker()
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self._load_resources()

    def _load_resources(self):
        try:
            logger.info(f"Loading resources from {CONFIG['MODEL_PATH']}...")
            data = joblib.load(CONFIG['MODEL_PATH'])
            
            if isinstance(data, dict):
                self.model = data.get('model')
                self.scaler = data.get('scaler')
                self.label_encoder = data.get('label_encoder')
            else:
                self.model = data
            
            # Patch XGBoost
            if hasattr(self.model, 'estimators_'):
                 for est in self.model.estimators_:
                     try: est.get_booster().feature_names = None
                     except: pass
            
            if not self.scaler:
                logger.warning("⚠ NO SCALER DETECTED. Using Emergency Log-Normalization.")
                
        except Exception as e:
            logger.critical(f"Failed to load model: {e}")
            sys.exit(1)

    def extract_features(self, packet, duration, rate, syn_count):
        f = {k: 0.0 for k in EXPECTED_FEATURES}
        
        f['flow_duration'] = duration
        f['duration'] = duration
        f['rate'] = rate
        f['srate'] = rate
        f['syn_count'] = float(syn_count)
        f['tot_size'] = float(len(packet))
        
        if IP in packet:
            f['header_length'] = float(packet[IP].ihl * 4)
            f['tcp'] = 1.0 if TCP in packet else 0.0
            f['udp'] = 1.0 if UDP in packet else 0.0
            f['icmp'] = 1.0 if ICMP in packet else 0.0
            
            if TCP in packet:
                flags = packet[TCP].flags
                f['syn_flag_number'] = 1.0 if 'S' in flags else 0.0
                f['ack_flag_number'] = 1.0 if 'A' in flags else 0.0
                f['fin_flag_number'] = 1.0 if 'F' in flags else 0.0
                f['rst_flag_number'] = 1.0 if 'R' in flags else 0.0
                f['psh_flag_number'] = 1.0 if 'P' in flags else 0.0
                p = packet[TCP].dport
                f['http'] = 1.0 if p == 80 else 0.0
                f['https'] = 1.0 if p == 443 else 0.0
                f['ssh'] = 1.0 if p == 22 else 0.0
                
            l = float(len(packet))
            f['min'] = l; f['max'] = l; f['avg'] = l; f['tot_sum'] = l

        return pd.DataFrame([f], columns=EXPECTED_FEATURES)

    def predict(self, packet):
        # 1. NOISE FILTER
        if not packet.haslayer(IP): return
        src = packet[IP].src
        dst = packet[IP].dst
        if dst in CONFIG["IGNORED_IPS"] or dst.startswith("224.0.0."): return

        # 2. UPDATE STATE
        dur, rate, syns, unique_ips, unique_ports = self.tracker.update(src, dst, packet)
        
        # 3. ML INFERENCE
        input_df = self.extract_features(packet, dur, rate, syns)
        
        # Scaling
        if self.scaler:
            try: input_data = self.scaler.transform(input_df)
            except: input_data = input_df
        else:
            cols_to_squash = ['flow_duration', 'rate', 'srate', 'tot_size', 'tot_sum']
            for col in cols_to_squash:
                if col in input_df.columns: input_df[col] = np.log1p(input_df[col])
            input_data = input_df

        try:
            probs = self.model.predict_proba(input_data)[0]
            conf = np.max(probs)
            pred_idx = np.argmax(probs)
            
            label = str(pred_idx)
            if self.label_encoder:
                label = self.label_encoder.inverse_transform([pred_idx])[0]
            elif pred_idx in CONFIG["MANUAL_MAPPING"]:
                label = CONFIG["MANUAL_MAPPING"][pred_idx]

            # 4. HEURISTICS
            final_label = self._apply_heuristics(label, rate, conf, packet, unique_ips, unique_ports)
            
            if final_label:
                self._alert(src, dst, final_label, conf, rate, unique_ips, unique_ports)

        except Exception as e:
            pass

    def _apply_heuristics(self, label, rate, conf, packet, unique_ips, unique_ports):
        lbl = str(label)
        
        # RULE 1: Filter Benign / Low Conf
        if lbl.lower() in ["benign", "normal", "0"]: return None
        if conf < CONFIG["CONFIDENCE_THRESHOLD"]: return None

        # RULE 2: NETSCAN (Many IPs)
        if unique_ips > CONFIG["SCAN_IP_THRESHOLD"]:
            return "Network-Scan (Discovery)"

        # RULE 3: PORTSCAN (Many Ports)
        if unique_ports > CONFIG["SCAN_PORT_THRESHOLD"]:
            return "PortScan (Enumeration)"

        # RULE 4: WEB TRAFFIC FIX (Rate/Ports check)
        # If "DoS" predicted but rate is low or ports are few, check if it's benign
        if "DoS" in lbl:
            if rate < CONFIG["DOS_RATE_THRESHOLD"]:
                # If only hitting 1 or 2 ports slowly, it's likely web traffic
                if unique_ports <= 2:
                    return None
                return "PortScan (Stealth)"

        # RULE 5: REAL DOS CHECK
        if "DoS" in lbl and rate > CONFIG["DOS_RATE_THRESHOLD"]:
            return lbl

        return lbl

    def _alert(self, src, dst, label, conf, rate, unique_ips, unique_ports):
        color = "\033[91m" if "DoS" in label else "\033[93m"
        end = "\033[0m"
        
        if "Scan" in label:
            msg = f"{color}[!] ALERT: {label} | Src: {src} | Targets: {unique_ips} IPs / {unique_ports} Ports | Rate: {rate:.0f} p/s{end}"
        else:
            msg = f"{color}[!] ALERT: {label} | Src: {src} -> {dst} | Rate: {rate:.0f} p/s | Conf: {conf:.2f}{end}"
            
        print(msg)
        try:
            requests.post(CONFIG["API_URL"], json={
                "timestamp": time.time(),
                "type": label,
                "src_ip": src,
                "dst_ip": dst,
                "confidence": float(conf),
                "meta": f"Rate: {rate:.1f}, Targets: {unique_ips}, Ports: {unique_ports}"
            }, timeout=0.1)
        except: pass

# ==============================================================================
# 4. MAIN
# ==============================================================================
def main():
    if os.geteuid() != 0:
        print("Error: Root privileges required. Use 'sudo python3 sniffer.py'")
        sys.exit(1)
        
    print(f"[*] IDS Agent Active on {CONFIG['INTERFACE']}")
    engine = IDSEngine()
    try:
        sniff(iface=CONFIG['INTERFACE'], prn=engine.predict, store=0, filter="ip")
    except KeyboardInterrupt:
        print("\n[*] Stopping.")

if __name__ == "__main__":
    main()