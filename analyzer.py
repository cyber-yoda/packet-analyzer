#!/usr/bin/env python3

import os

from scapy.all import *
from scapy.all import rdpcap
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, UDP

def analyze_pcap(filename):
    try:
        packets = rdpcap(filename)
    except FileNotFoundError:
        print(f"[!] File not found > {filename}")
        return 

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            info = f"{ip_layer.src} -> {ip_layer.dst}"

            if TCP in pkt:
                tcp = pkt[TCP]
                info += f" | TCP {tcp.sport} -> {tcp.dport}"
            
            elif UDP in pkt:
                udp = pkt[UDP]
                info += f" | UDP {udp.sport} -> {udp.dport}"

            elif pkt.haslayer(HTTPRequest):
                http = pkt[HTTPRequest]
                try:
                    info += f" | HTTP {http.Method.decode()} {http.Host.decode()}{http.Path.decode()}"
                except:
                    info += f" | HTTP Request (parse error)"

            print(info)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <file.pcap>")
        return
    analyze_pcap(sys.argv[1])

if __name__ == "__main__":
    main()

