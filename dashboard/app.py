import logging
from flask import Flask, request, jsonify, render_template
import time
from collections import deque
import threading

app = Flask(__name__)

# Configuration
MAX_ALERTS = 100
alerts_buffer = deque(maxlen=MAX_ALERTS)
status_lock = threading.Lock()
current_status = "SAFE"
last_alert_time = 0

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IDS_Backend")

def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    return response

@app.route('/api/alert', methods=['POST', 'OPTIONS'])
def receive_alert():
    global current_status, last_alert_time
    
    if request.method == 'OPTIONS':
        return add_cors_headers(jsonify({}))

    try:
        data = request.json
        if not data:
            return add_cors_headers(jsonify({"error": "No data"})), 400

        # Log the alert
        alert_entry = {
            "timestamp": data.get("timestamp", time.time()),
            "src_ip": data.get("src_ip", "Unknown"),
            "dst_ip": data.get("dst_ip", "Unknown"),
            "type": data.get("type", "Unknown"),
            "confidence": data.get("confidence", 0.0)
        }
        
        with status_lock:
            alerts_buffer.appendleft(alert_entry)
            current_status = "DANGER"
            last_alert_time = time.time()
            
        logger.warning(f"ALERT RECEIVED: {alert_entry}")
        return add_cors_headers(jsonify({"status": "received"})), 200

    except Exception as e:
        logger.error(f"Error processing alert: {e}")
        return add_cors_headers(jsonify({"error": str(e)})), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    global current_status
    
    # Auto-reset status to SAFE if no alerts for 10 seconds? 
    # User didn't specify, but "Auto-refreshing UI" implies dynamic status.
    # Let's keep it simple: specific alert overrides safe. 
    # I'll implement a simple timeout for the "Red Card" effect (e.g. 5 seconds).
    
    with status_lock:
        if current_status == "DANGER" and (time.time() - last_alert_time > 10):
            current_status = "SAFE"
        
        response_data = {
            "status": current_status,
            "latest_alerts": list(alerts_buffer)
        }
    
    return add_cors_headers(jsonify(response_data))

@app.route('/')
def index():
    # Helper to serve dashboard if they are in the same dir
    try:
        return render_template('dashboard.html')
    except Exception as e:
        return f"Error loading dashboard: {e}"

if __name__ == '__main__':
    print("Starting IDS Backend HQ on 0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
