'''
Coded by Daniel Rodriguez, Simran Gupta, Nicolas Pacheco
Date: 7/7/2026
'''

from flask import Flask, jsonify, send_from_directory
from scapy.all import sniff, IP
from collections import Counter, deque
from datetime import datetime
import threading
import subprocess
import re
import itertools

# Point Flask precisely to your current project folder
app = Flask(__name__, static_folder='.', template_folder='.')

# Fast in-memory array to store packets without hitting the SD card
packet_buffer = deque(maxlen=200)

# In-memory store of Suricata alerts (most recent 200)
alert_buffer = deque(maxlen=200)
alert_id_counter = itertools.count(1)

SURICATA_LOG_PATH = "/var/log/suricata/fast.log"

# Matches classic Suricata fast.log lines, e.g.:
# 07/07/2026-12:34:56.789012  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**]
# [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.5:1234 -> 192.168.1.1:80
FAST_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(?P<msg>.*?)\s+\[\*\*\]\s+"
    r"\[Classification:\s*(?P<classification>.*?)\]\s+\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<proto>\w+)\}\s+(?P<src>[\d.]+)(?::(?P<sport>\d+))?\s+->\s+(?P<dst>[\d.]+)(?::(?P<dport>\d+))?"
)

PRIORITY_TO_SEVERITY = {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}


def parse_fast_log_line(line):
    """Parse a single Suricata fast.log line into the alert dict shape script.js expects."""
    match = FAST_LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()

    # fast.log timestamps look like 07/07/2026-12:34:56.789012
    try:
        ts = datetime.strptime(data["timestamp"].split(".")[0], "%m/%d/%Y-%H:%M:%S")
        time_str = ts.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        time_str = data["timestamp"]

    severity = PRIORITY_TO_SEVERITY.get(data["priority"], "MEDIUM")
    src_ip = data["src"] + (f":{data['sport']}" if data.get("sport") else "")
    target = data["dst"] + (f":{data['dport']}" if data.get("dport") else "")

    return {
        "id": next(alert_id_counter),
        "title": data["msg"],
        "description": f"{data['classification']} ({data['proto']})",
        "severity": severity,
        "status": "ACTIVE",
        "sourceIp": src_ip,
        "target": target,
        "time": time_str,
    }


def live_alert_tailer():
    """Background thread that tails Suricata's fast.log and parses new alerts as they arrive."""
    while True:
        try:
            # -F follows the file across log rotation; -n0 skips existing history on startup
            process = subprocess.Popen(
                ["sudo", "tail", "-F", "-n", "0", SURICATA_LOG_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                alert = parse_fast_log_line(line)
                if alert:
                    alert_buffer.append(alert)
        except Exception as e:
            print(f"Alert tailer error: {e}")
            threading.Event().wait(2)

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
    try:
        current_alerts = list(alert_buffer)
        current_alerts.reverse()  # newest first
        return jsonify({
            "alerts": current_alerts,
            "alert_count": len(current_alerts),
        })
    except Exception as e:
        return jsonify({"error": str(e), "alerts": [], "alert_count": 0})

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

    # Fire up the background Suricata alert tailer
    alert_thread = threading.Thread(target=live_alert_tailer, daemon=True)
    alert_thread.start()

    # Run the webapp with full multi-threading enabled
    app.run(host="0.0.0.0", port=5000, threaded=True)
