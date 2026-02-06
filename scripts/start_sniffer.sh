#!/bin/bash
# Conveniently run the sniffer with sudo and the virtual environment
echo "[*] Starting IDS Sniffer via sudo + venv..."
sudo ./venv/bin/python sniffer.py
python server.py
