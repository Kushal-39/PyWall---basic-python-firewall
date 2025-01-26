import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

THRESHOLD = 40
print(f"Threshold set to {THRESHOLD}")

def packet_callback(packet):
    src_ip=packet[IP].src
    packet_count[src_ip]+=1
    current_time=time.time()
    time_diff=current_time-start_time[0]
    
    if time_diff >=1:
        for ip,count in packet_count.items():
            packet_rate= count/time_diff
            if packet_rate > THRESHOLD:
                print(f"Threshold exceeded for {ip} at {packet_rate}, Blocking IP")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)
        
        packet_count.clear()
        start_time[0]=current_time


if __name__ == "__main__":
    if os.geteuid()!=0:
        print("Run as root")
        sys.exit(1)
    
    packet_count=defaultdict(int)
    start_time=[time.time()]
    blocked_ips=set()
    
    print("Starting packet capture")
    sniff(filter="ip",prn=packet_callback)