#!/usr/bin/env python3

import os
import re
import sys
from scapy.all import *
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

        if pkt.haslayer(layer_name):
            layer = pkt[layer_name]

            if hasattr(layer, field):
                try:
                    value = getattr(layer, field)
                    if isinstance(value, bytes):
                        value = value.decode(errors='ignore')

                    if pattern and re.search(pattern, value, re.I):
                        alerts.append({
                            "severity": "[!] VULNERABLE",
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

    print("\n==== HOSTS IP:PORT INFORMATION ====\n")

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            proto_label = "IP"
            sport = dport = "-"

            if TCP in pkt:
                proto_label = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                proto_label = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            print(f"{ip_layer.src}:{sport} | {proto_label} -> {ip_layer.dst}:{dport} | {proto_label}")
            print(f"{ip_layer.dst}:{dport} | {proto_label} <- {ip_layer.src}:{sport} | {proto_label}")

            if pkt.haslayer(HTTPRequest):
                http = pkt[HTTPRequest]
                try:
                    method = http.Method.decode()
                    host = http.Host.decode()
                    path = http.Path.decode()
                    print(f"\n==== Endpoint & Name Resolution ====")
                    print(f"{method} http://{host}{path}")
                except:
                    print(f" [!] HTTP Parse Error")

            alerts = detect_patterns(pkt)
            if alerts:
                for alert in alerts:
                    print(f"    {alert['severity']} {alert['message']}")
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
