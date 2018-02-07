#!/usr/bin/env python
import argparse, sys, os
from collections import deque
from scapy.all import *

# use deque for faster queueing
packet_queue = deque(maxlen=20)

def dns_detect(packet):
    if not packet.haslayer(DNSRR): return
    if len(packet_queue):
        for op in packet_queue:
            if op[IP].dst == packet[IP].dst and\
            op[IP].sport == packet[IP].sport and\
            op[IP].dport == packet[IP].dport and\
            op[IP].payload != packet[IP].payload and\
            op[DNSRR].rdata != packet[DNSRR].rdata and\
            op[DNS].id == packet[DNS].id and\
            op[DNS].qd.qname == packet[DNS].qd.qname:
                request = op[DNS].qd.qname.decode(encoding='UTF-8')
                request = request[:-1] if request.endswith('.') else request
                print("DNS poisoning attempt")
                print("TXID", op[DNS].id, end=' ')
                print("Request", request)
                print("Answer1 [{}]".format(op[DNSRR].rdata))
                print("Answer2 [{}]".format(packet[DNSRR].rdata))
    packet_queue.append(packet)

def parse_options():
    parser = argparse.ArgumentParser(description="DNS poisoning detect tool.")
    parser.add_argument("-i", default="")
    parser.add_argument("-r", default="")
    parser.add_argument('expression')
    args = parser.parse_args()

    return args.i, args.r, args.expression

if __name__ == '__main__':
    interface, tracefile, expression = parse_options()
    defaultif = 'ens33'
    # check input
    if interface and tracefile:
        print("Invalid input. Please input in following format.")
        print("dnsdetect [-i interface] [-r tracefile] expression")
        sys.exit()
    elif interface: print("interface:", interface)
    elif tracefile: print("tracefile:", tracefile)
    else:
        print("Invalid input. Please input in following format.")
        print("dnsdetect [-i interface] [-r tracefile] expression")
        sys.exit()
    if expression: print("expression:", expression)

    if interface: 
        sniff(filter=expression, iface=interface, prn=dns_detect)
    elif tracefile: 
        sniff(filter=expression, offline=tracefile, prn=dns_detect)
    else: sniff(filter=expression, iface=defaultif, prn=dns_detect)