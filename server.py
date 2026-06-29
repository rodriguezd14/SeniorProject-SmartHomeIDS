from flask import Flask, jsonify, send_from_directory
from scapy.all import sniff, IP
from collections import Counter, deque
from datetime import datetime
import threading
import json
import os
import time
import itertools

# Point Flask precisely to your current project folder
app = Flask(__name__, static_folder='.', template_folder='.')

# Fast in-memory array to store packets without hitting the SD card
packet_buffer = deque(maxlen=200)

#---Suricata alert state-----------------------------------------------------
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"
SEVERITY_MAP = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
DEDUP_WINDOW_SECONDS = 20 #ignore repeatalerts for the same signature+source this often
alert_buffer = deque(maxlen=100) #newest-last; dashbord reads the latest 50
recent_alert_keys = {}

def process_alert_event(event):
	"""Take one parsed Suricata 'alert' event from eve.json and store it for the dashboard."""
	alert_data = event.get("alert", {})
	signature = alert_data.get("signature", "Unknown Alert")
	signature_id = alert_data.get("signature_id")
	category = alert_data.get("category", "Uncategorzied")
	severity_num = alert_data.get("severity", 3)
	src_ip = event.get("src_ip", "unknown")
	dest_ip = event.get("dest_ip", "unknown")
	
	dedup_key = (signature_id, src_ip)
	now = time.time()
	last_seen = recent_alert_keys.get(dedup_key)
	if last_seen and (now - last_seen) < DEDUP_WINDOW_SECONDS:
		return
	recent_alert_keys[dedup_key] = now

	alert_buffer.append({
		"id": next(alert_id_counter),
		"title": signature,
		"description": f"{category} - traffic from {src_ip} to {dest_ip}",
		"severity": SEVERITY_MAP.get(severity_num, "LOW"),
		"status": "ACTIVE",
		"sourceIP": src_ip,
		"target": dest_ip,
		"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
	})

def tail_suricata_alerts():
	"""Background thread that tails Suricaata's eve.json and feeds new alerts into alert_buffer."""
	while not os.path.exists(SURICAATA_LOG_PATH):
		print("Waiting for Suricata log file to appear at", SURICARA_LOG_PATH)
		time.sleep(2)

	with open (SURICATA_LOG_PATH, "r") as f:
		f.seek(0, os.SEEK_END)
		while True:
			line = f.readline()
			if not line:
				time.sleep(0.5)
				continue
			try:
				event = json.loads(line)
			except json.JSONDecodeError:
				continue
			if event.get("event_type") == "alert":
				process_alert_event(event)

def live_packet_sniffer():
    """Background thread that captures live packets on eth0 safely."""
    def process_packet(pkt):
        if IP in pkt:
            packet_buffer.append(pkt)

    while True:
        try:
            # 2-second timeout windows keeps the thread highly responsive
            sniff(iface="ens33", prn=process_packet, store=0, timeout=2)
        except Exception as e:
            print(f"Sniffer error: {e}")

@app.route("/api/traffic")
def get_traffic():
    try:
        packet_log = []
        devices = {}
        protocols = Counter()

        # Snapshot the current RAM buffer
        current_packets = list(packet_buffer)

        for pkt in current_packets:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto_num = pkt[IP].proto

            if proto_num == 6: proto = "TCP"
            elif proto_num == 17: proto = "UDP"
            elif proto_num == 1: proto = "ICMP"
            else: proto = "OTHER"

            protocols[proto] += 1
            
            # Match the exact dictionary syntax your frontend script parses
            packet_log.append({
                "time": datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S"),
                "source": src,
                "destination": dst,
                "protocol": proto,
                "size": round(len(pkt) / 1024, 2),
                "status": "ALLOWED"
            })
            devices[src] = True
            devices[dst] = True

        # Return the exact keys script.js needs to render tables and graphs
        return jsonify({
            "packet_count": len(packet_log),
            "packets": packet_log[-100:],  # Send the latest 100 packets to fill log rows
            "devices": list(devices.keys()),
            "protocols": dict(protocols)
        })

    except Exception as e:
        return jsonify({"error": str(e), "packets": [], "packet_count": 0})

@app.route("/api/alerts")
def get_alerts():
    return jsonify({"alerts": list(alert_buffer)[-50:0]})

# --- Web Server Asset Core Endpoints ---
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/script.js")
def javascript():
    return send_from_directory(".", "script.js")

@app.route("/styles.css")
def styles():
    return send_from_directory(".", "styles.css")

if __name__ == "__main__":
    # Fire up the background sniffer engine
    sniffer_thread = threading.Thread(target=live_packet_sniffer, daemon=True)
    sniffer_thread.start()

    alert_thread = threading.Thread(target=tail_suricata_alerts, daemon=True)
    alert_thread.start()

    # Run the webapp with full multi-threading enabled
    app.run(host="0.0.0.0", port=5000, threaded=True)
