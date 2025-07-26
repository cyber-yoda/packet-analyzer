#!/usr/bin/env python3

import os
import re                        # Detection Rules REQUIRED the ability to search Registry Expressions
import sys
from scapy.all import *
from scapy.all import rdpcap
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, UDP

DETECTION_RULES = [
    {
        "name": "SQLi in HTTP Path",
        "layer": "HTTPRequest",
        "field": "Path",
        "pattern": r"(union\s+select|or\s+1=1|--|;--)",
    },
    {
        "name": "CMD Inj. in HTTP Path",
        "layer": "HTTPRequest",
        "field": "Path",
        "pattern": r"[;&|`]",
    },
    {
        "name": "Suspicious USER AGENT",
        "layer": "HTTPRequest",
        "field": "User_Agent",
        "pattern": r"(curl|wget|python-request)", 
    },
]

print(" [+] Successfully imported HTTP Layer")

def detect_patterns(pkt):
    alerts = []

    for rule in DETECTION_RULES:
        layer_name = rule.get("layer")
        field = rule.get("field")
        pattern = rule.get("pattern")
        action = rule.get("action")

        if pkt.haslayer(layer_name):
            layer = pkt[layer_name]

            if hasattr(layer, field):
                try:
                    value = getattr(layer, field)
                    if isinstance(value, bytes):
                        value = value.decode(errors='ignore')

                    elif pattern and re.search(pattern, value, re.I):
                        alerts.append[{
                            "severity": "[!] VULNERABLE"
                            "message": rule["name"]
                        })
                        elif pattern and re.search(value):
                            alert.append({
                                "severity": "[!] SUSPICIOUS",
                                "message": rule["name"]
                            })
                            
                except Exception:
                        continue
        return alerts
            
def analyze_pcap(filename):
    try:
        packets = rdpcap(filename)
    except FileNotFoundError:
        print(f"[!] File not found > {filename}")
        return 

    print("\n==== HOSTS IP:PORT INFORMATION ====\n") # Added print statement before 'for pkt in packets:' 

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            proto = "IP/Other"
            sport = dport = "-"
            proto_label = ""

            if TCP in pkt:
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                proto_label = "TCP"
            elif UDP in pkt:
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                proto_label = "UDP"

            print(f"{ip_layer.src}:{sport} | {proto_label} -> {ip_layer.dst}:{dport} | {proto_label}")
            print(f"{ip_layer.dst}:{dport} | {proto_label} <- {ip_layer.src}:{sport} | {proto_lable}")

            # HTTP Host/Path Parsing
            elif pkt.haslayer(HTTPRequest):
                http = pkt[HTTPRequest]
                try:
                    method = http.Method.decode()
                    host = http.Host.decode()
                    path = http.Path.decode()
                    print(f"\n==== Endpoint & Name Resolution ====")
                    print(f"{method} http://{host}{path}")
                except:
                    print(f" [!] HTTP Parse Error")

            # Added in Detection out to utilize DETECTION_RULES
            alerts = detect_patterns(pkt)
            if alerts:
                for alert in alerts:
                    print(f"    [{alert['Severity']}] {alert['message']}")
            else:
                print(" [+] [CLEAN] No known exploit patterns detected.")
            print("-" * 60)
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <file.pcap>")
        return
    analyze_pcap(sys.argv[1])

if __name__ == "__main__":
    main()

