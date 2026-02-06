# NeuralGuard: Hybrid AI-Powered IDS for IoT Networks

![Python](https://img.shields.io/badge/Python-3.10-blue?style=for-the-badge&logo=python)
![ML](https://img.shields.io/badge/AI-RandomForest%20%2B%20XGBoost-orange?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Scapy%20Sniffer-red?style=for-the-badge)

**NeuralGuard** is a lightweight, real-time Intrusion Detection System (IDS) designed for IoT environments. Unlike traditional signature-based systems, it uses an **Ensemble Machine Learning model** (Random Forest + XGBoost) to detect zero-day anomalies. 

It features a custom **State-Based Flow Tracker** that eliminates common false positives (e.g., distinguishing between a legitimate DNS query, a Port Scan, and a DDoS attack).

## 📸 Dashboard
![Dashboard Screenshot](screenshots/dashboard_view.png)
*(Place your screenshot of the "SECURE" green screen here)*

## 🚀 Key Features

* **Real-Time Traffic Analysis:** Captures and analyzes packets on the fly using `Scapy`.
* **Hybrid Detection Engine:**
    * **Layer 1:** Noise Filter (Ignores Multicast, Broadcast, Localhost).
    * **Layer 2:** ML Inference (46-feature vector analysis).
    * **Layer 3:** Contextual Heuristics (Logic gates to validate ML predictions).
* **Smart State Tracking:** * Distinguishes **Nmap Scans** (Many Ports) from **DDoS Floods** (High Rate).
    * Identifies **Network Sweeps** (Many IPs).
* **Robustness:** Includes an "Emergency Log-Scaler" to handle unscaled input data without crashing.

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.8+
* Root/Administrator privileges (for packet sniffing)
* VirtualBox (if testing in a Host-Only lab)

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/NeuralGuard-IDS.git
cd NeuralGuard-IDS
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the System
**Step A: Start the Dashboard (Host)**
```bash
cd dashboard
python app.py
```

**Step B: Start the Sniffer (Victim VM)**
```bash
cd ids_core
sudo python3 sniffer.py
```

## 🧪 Testing the IDS

You can simulate attacks using Kali Linux to verify detection.

| Attack Type | Command | Expected Result |
| :--- | :--- | :--- |
| **DDoS (TCP)** | `hping3 -S --flood -p 80 <IP>` | `[!] ALERT: DDoS-TCP | Rate: >1000 p/s` |
| **Port Scan** | `nmap -sS -p 1-1000 <IP>` | `[!] ALERT: PortScan | Targets: >5 Ports` |
| **Ping Sweep** | `nmap -sn <Subnet>` | `[!] ALERT: Network-Scan | Targets: >5 IPs` |
| **Web Traffic** | `curl http://<IP>` | **Ignored (Benign)** |

## 🧠 How It Works (The Logic)

1.  **Packet Capture:** The system listens on the raw interface (`eth0` or `vboxnet0`).
2.  **Flow Extraction:** Packets are grouped into flows. Features like `Flow Duration`, `IAT`, and `Packet Size` are calculated.
3.  **ML Prediction:** The Ensemble model predicts a class (e.g., `DDoS-UDP`).
4.  **Heuristic Validation:** The system checks the context:
    * *Is the rate high enough for a DDoS?*
    * *Are multiple ports being hit?*
    * *Is this just a server responding to a client?*
5.  **Alerting:** Validated threats are sent to the Flask API and logged to the dashboard.

## ⚠️ Disclaimer
This project is for **educational purposes only**. Do not use these tools on networks you do not own or have explicit permission to test.


## 🔧 Troubleshooting

* **VirtualBox Interface:** If running the sniffer inside a VM, ensure the interface in `ids_core/sniffer.py` is set to `eth0` (or your VM's interface name). If running on the Host, set it to `vboxnet0`. 
* **API Connection:** Update the `API_URL` in `sniffer.py` to point to your Host IP (Gateway) if running the sniffer inside a VM and dashboard on the host.
