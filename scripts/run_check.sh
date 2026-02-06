#!/bin/bash
# Conveniently run the diagnostic check with sudo and the virtual environment
echo "[*] Running Diagnostic Tool via sudo + venv..."
sudo ./venv/bin/python check_setup.py
