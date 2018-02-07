## Description:
dnsinject.py is the DNS packet injector. Attacker sniffs a given interface, constructs false DNS responses to specific queries, and sends the false response in hopes of reaching the victim before legit response from DNS server; 
dnsdetect.py is the passive DNS poisoning attack detector. Victim sniffs given interface or pcap file and tries to detect if similar dns response packets appear in a short window time (since it is normal for hostnames to modify its resolved ip addresses over time);
File 'hostnames' contains a list of ip & hostname pairs to be used for injection;
File 'trace.pcap' contains 2 poisoning attacks that failed and 1 attack that won the race condition.

## For false positives of dnsdetect:
A queue of maxlength 20 packets is used to show low latency between the fake and legit response. Once a packet is sniffed, it is compared to the older packets in the queue, and if ip,port,hostname,etc is the same and only the DNS response data is different then the program reports this as a DNS poison attempt. This distinguishes most valid response pairs from the poisoning attempts. However, there still are special scenarios where this might not be enough to evaluate, as discussed in piazza #169. This kind of scenario is ignored.

## Environment & Dependencies:
Two VMs in a bridged network with internet connection;
Python3 + scapy package under Ubuntu 16.04.
`sudo apt install python3-pip`
`sudo pip3 install scapy-python3`

## Usage:
sudo python3 dnsinject.py [-i interface] [-f hostnames] expression
sudo python3 dnsdetect.py [-i interface] [-r tracefile] expression
### Examples:
sudo python3 dnsinject.py
sudo python3 dnsinject.py -i ens33 -f hostnames 
sudo python3 dnsdetect.py -i ens33 'udp port 53'
sudo python3 dnsdetect.py -r trace.pcap 'udp port 53'

### Sample output of dnsdetect:
$sudo python3 dnsdetect.py -r trace.pcap 'udp port 53'
Output:
tracefile: trace.pcap
expression: udp port 53
DNS poisoning attempt
TXID 40316 Request example.com
Answer1 [93.184.216.34]
Answer2 [192.168.43.53]
DNS poisoning attempt
TXID 55318 Request yahoo.com
Answer1 [98.138.252.38]
Answer2 [192.168.43.53]
DNS poisoning attempt
TXID 32799 Request abc.com
Answer1 [192.168.43.53]
Answer2 [199.181.132.250]

## References:
https://github.com/secdev/scapy/blob/master/scapy/layers/dns.py
https://thepacketgeek.com/scapy-p-09-scapy-and-dns/
https://docs.python.org/3/library/argparse.html
