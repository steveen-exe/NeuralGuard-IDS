#!/usr/bin/env python3
# ==============================================================================
# NEURALGUARD: GOLDEN PRODUCTION SNIFFER (v3.0 - Final)
# Deployed on: Gateway (192.168.56.1)
# Features: 
#   - Stability Filter (Fixes Ping False Positives)
#   - Server Exclusion (Fixes Web Browsing False Positives)
#   - Priority Logic (Scan > DDoS > ML)
# ==============================================================================

import sys
import time
import logging
import joblib
import pandas as pd
import numpy as np
import requests
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ================= CONFIGURATION =================
CONFIG = {
    # Interface: 'vboxnet0' for Host-Only Gateway / 'eth0' for VM
    "INTERFACE": "vboxnet0",  
    
    "MODEL_PATH": "ids_ensemble_final.pkl",
    "API_URL": "http://127.0.0.1:5000/api/alert",
    
    # --- DETECTION THRESHOLDS ---
    "DOS_RATE_THRESHOLD": 50.0,       # >50 p/s on SINGLE port = DDoS
    "SCAN_PORT_THRESHOLD": 2,         # >2 unique ports = Port Scan (Highest Priority)
    "SILENCE_THRESHOLD": 10.0,        # Ignore flows < 10 p/s (Noise Filter)
    
    # --- NOISE FILTER (Ignored IPs) ---
    "IGNORED_IPS": [
        "224.0.0.22", "239.255.255.250", "255.255.255.255", 
        "127.0.0.1", "0.0.0.0"
    ],
    
    # ML Label Mapping (Fallback)
    "MANUAL_MAPPING": {
        0: "Benign", 1: "DDoS-TCP", 2: "DDoS-UDP", 
        3: "PortScan", 4: "Mirai-Botnet", 5: "DDoS-ICMP"
    }
}

# Features required by the ML Model (46 Total)
EXPECTED_FEATURES = [
     'flow_duration', 'header_length', 'protocol_type', 'duration', 'rate', 'srate', 'drate',
     'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
     'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count',
     'rst_count', 'http', 'https', 'dns', 'telnet', 'smtp', 'ssh', 'irc', 'tcp', 'udp', 'dhcp',
     'arp', 'icmp', 'ipv', 'llc', 'tot_sum', 'min', 'max', 'avg', 'std', 'tot_size', 'iat',
     'number', 'radius', 'covariance', 'variance', 'weight', 'magnitude'
]

logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s', level=logging.INFO)
logger = logging.getLogger("IDS_Core")

class FlowTracker:
    """Tracks state of network flows to distinguish Attack Types"""
    def __init__(self):
        self.flows = {}
        self.last_cleanup = time.time()

    def update(self, src, dst, packet):
        now = time.time()
        
        # 1. CLEANUP (Memory Management)
        if now - self.last_cleanup > 2.0:
            self.flows = {k: v for k, v in self.flows.items() if (now - v['last']) < 5.0}
            self.last_cleanup = now

        # 2. KEY GENERATION (Isolate Protocols)
        # Prevents Ping packets from affecting TCP stats
        proto = 'ICMP' if packet.haslayer(ICMP) else 'TCP/UDP'
        key = (src, dst, proto)

        if key not in self.flows:
            self.flows[key] = {
                'start': now, 'count': 0, 'last': now, 
                'ports': set(), 'syns': 0
            }
        
        f = self.flows[key]
        
        # 3. ROLLING WINDOW RESET
        # If flow gap > 3s, reset stats (Treat as new burst)
        if (now - f['start']) > 3.0:
            f['start'] = now
            f['count'] = 0
            f['ports'] = set()
            f['syns'] = 0

        f['count'] += 1
        f['last'] = now
        
        # 4. PORT TRACKING & SERVER EXCLUSION
        is_server_reply = False
        if packet.haslayer(TCP):
            # Ignore RST packets (Backscatter from closed ports)
            if 'R' in packet[TCP].flags: return None
            
            # Don't count Source Ports 80/443/22 as "Scanned Ports" (Server Replying)
            if packet[TCP].sport in [80, 443, 8080, 22, 5000]: is_server_reply = True
            
            if not is_server_reply: 
                f['ports'].add(packet[TCP].dport)
            
            if 'S' in packet[TCP].flags: 
                f['syns'] += 1
                
        elif packet.haslayer(UDP):
            if packet[UDP].sport in [53]: is_server_reply = True
            if not is_server_reply: f['ports'].add(packet[UDP].dport)

        # 5. STATS CALCULATION
        dur = now - f['start']
        safe_dur = dur if dur > 0.001 else 0.001
        rate = f['count'] / safe_dur
        
        # Return count for Stability Check
        return dur, rate, len(f['ports']), f['syns'], f['count']

class IDSEngine:
    def __init__(self):
        self.tracker = FlowTracker()
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self._load_resources()

    def _load_resources(self):
        try:
            if not os.path.exists(CONFIG['MODEL_PATH']): 
                logger.warning("⚠ Model file not found. Running in Heuristic Mode.")
                return

            data = joblib.load(CONFIG['MODEL_PATH'])
            
            # Unpack Dictionary vs Raw Model
            if isinstance(data, dict):
                self.model = data.get('model')
                self.scaler = data.get('scaler')
                self.label_encoder = data.get('label_encoder')
            else:
                self.model = data
            
            # XGBoost Compatibility Patch
            if hasattr(self.model, 'estimators_'):
                 for est in self.model.estimators_:
                     try: est.get_booster().feature_names = None
                     except: pass
                     
            logger.info("✅ Resources loaded successfully.")
        except Exception as e:
            logger.error(f"Load Error: {e}")

    def extract_features(self, packet, duration, rate):
        f = {k: 0.0 for k in EXPECTED_FEATURES}
        f['flow_duration'] = duration; f['duration'] = duration; f['rate'] = rate
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
                f['rst_flag_number'] = 1.0 if 'R' in flags else 0.0
                f['fin_flag_number'] = 1.0 if 'F' in flags else 0.0

        return pd.DataFrame([f], columns=EXPECTED_FEATURES)

    def predict(self, packet):
        # 1. PROTOCOL FILTER
        if not packet.haslayer(IP): return
        src, dst = packet[IP].src, packet[IP].dst
        
        # 2. IP FILTER (Noise & Loopback)
        if dst in CONFIG["IGNORED_IPS"] or dst.startswith("224.0.0."): return
        if src == dst: return 
        
        # 3. API FILTER (Prevent Self-Detection of Port 5000 alerts)
        if packet.haslayer(TCP) and (packet[TCP].dport == 5000 or packet[TCP].sport == 5000): return

        # 4. UPDATE STATE
        result = self.tracker.update(src, dst, packet)
        if not result: return # Packet was ignored (e.g. RST)
        
        dur, rate, unique_ports, syns, count = result

        # --- STABILITY FILTER (FIX FOR NORMAL PING) ---
        # Don't judge the flow until we have seen at least 5 packets.
        # Normal ping (1 p/s) takes 5 seconds to pass this.
        # DDoS flood (1000 p/s) takes 0.005 seconds to pass this.
        if count < 5:
            return

        # 5. SILENCE GATE (Noise Filter)
        if rate < CONFIG["SILENCE_THRESHOLD"] and unique_ports < 2:
            return

        final_label = "Benign"
        conf = 0.0

        # --- HEURISTIC LOGIC (STRICT PRIORITY) ---
        
        # PRIORITY 1: PORT SCAN (Nmap)
        # If > 2 ports are hit, it is ALWAYS a scan, never a DDoS.
        if unique_ports >= CONFIG["SCAN_PORT_THRESHOLD"]:
            final_label, conf = "Recon (PortScan)", 0.99

        # PRIORITY 2: PING FLOOD (ICMP)
        # Must be ICMP and > 20 p/s
        elif packet.haslayer(ICMP) and rate > 20.0:
            final_label, conf = "DDoS-ICMP Flood", 0.99
            
        # PRIORITY 3: DDoS FLOOD (Hping3)
        # Must be Single Port + High Rate
        elif rate > CONFIG["DOS_RATE_THRESHOLD"]:
            if packet.haslayer(TCP): 
                # Differentiate SYN Flood vs Generic TCP
                final_label, conf = "DDoS-SYN Flood" if syns > 5 else "DDoS-TCP Flood", 0.98
            elif packet.haslayer(UDP): 
                final_label, conf = "DDoS-UDP Flood", 0.98

        # --- ML FALLBACK (Complex Attacks) ---
        else:
            if self.model and "Benign" in final_label:
                try:
                    input_df = self.extract_features(packet, dur, rate)
                    
                    # APPLY EMERGENCY SCALING (If scaler missing from .pkl)
                    if self.scaler:
                        input_data = self.scaler.transform(input_df)
                    else:
                        for c in ['flow_duration', 'rate', 'tot_size']: 
                            input_df[c] = np.log1p(input_df[c])
                        input_data = input_df

                    # PREDICT
                    probs = self.model.predict_proba(input_data)[0]
                    pred_idx = np.argmax(probs)
                    ml_conf = np.max(probs)
                    
                    # DECODE
                    ml_label = "Unknown"
                    if self.label_encoder:
                        ml_label = self.label_encoder.inverse_transform([pred_idx])[0]
                    elif pred_idx in CONFIG["MANUAL_MAPPING"]:
                        ml_label = CONFIG["MANUAL_MAPPING"][pred_idx]
                    
                    # SANITY CHECK
                    # If ML says DDoS but rate is low, ignore it (Hallucination)
                    if "DDoS" in ml_label and rate < 50:
                        pass
                    elif "Benign" not in ml_label:
                        final_label = ml_label
                        conf = ml_conf

                except Exception as e:
                    pass

        # 6. SEND ALERT
        if "Benign" not in final_label:
            self._alert(src, dst, final_label, conf, rate, unique_ports)

    def _alert(self, src, dst, label, conf, rate, ports):
        # Color Code: Red for DDoS, Yellow for Scan
        color = "\033[91m" if "DDoS" in label else "\033[93m"
        print(f"{color}[!] ALERT: {label} | Src: {src} -> {dst} | Rate: {rate:.1f} | Ports: {ports}\033[0m")
        try:
            requests.post(CONFIG["API_URL"], json={
                "timestamp": time.time(), "type": label, "src_ip": src, "dst_ip": dst,
                "confidence": float(conf), "meta": f"Rate: {rate:.1f}, Ports: {ports}"
            }, timeout=0.1)
        except: pass

def main():
    print(f"[*] NEURALGUARD PRODUCTION IDS ACTIVE ON {CONFIG['INTERFACE']}")
    engine = IDSEngine()
    try:
        sniff(iface=CONFIG['INTERFACE'], prn=engine.predict, store=0, filter="ip")
    except KeyboardInterrupt:
        print("\n[*] IDS Stopped.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()
