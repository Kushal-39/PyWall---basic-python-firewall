import os
import sys
import time
import json
from collections import defaultdict
from scapy.all import sniff, IP, TCP

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Read IPs from a file
def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)

# Check for Nimda worm signature
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False

# Log events to a file
def log_event(message, src_ip=None, attack_type=None, additional_info=None):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    log_file = os.path.join(log_folder, "firewall_logs.json")

    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "message": message,
        "src_ip": src_ip,
        "attack_type": attack_type,
        "additional_info": additional_info
    }

    with open(log_file, "a") as file:
        file.write(json.dumps(log_entry) + "\n")

        
# Check for SQL injection attempts
def is_sql_injection(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:  # HTTP traffic
        payload = str(packet[TCP].payload)
        sql_keywords = ["SELECT", "DROP", "INSERT", "UPDATE", "' OR '1'='1", "--", "/*", "*/", "xp_cmdshell"]
        for keyword in sql_keywords:
            if keyword.lower() in payload.lower():
                return True
    return False


# Check for SYN flood attack
syn_counts = defaultdict(int)

def detect_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":  # SYN flag
        src_ip = packet[IP].src
        syn_counts[src_ip] += 1
        
        if syn_counts[src_ip] > THRESHOLD:
            os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
            log_event(f"Blocking SYN flood IP: {src_ip}, SYN count: {syn_counts[src_ip]}")
            print(f"Blocking SYN flood IP: {src_ip}")
            syn_counts[src_ip] = 0  # Reset count after blocking

def packet_callback(packet):
    src_ip = packet[IP].src

      # Check if IP is in the whitelist
    if src_ip in whitelist_ips:
        return

    # Check for SQL injection attempts
    if is_sql_injection(packet):
        print(f"Blocking SQL injection source IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking SQL injection source IP: {src_ip}")
        return
    
    
    # Detect SYN flood attack
    detect_syn_flood(packet)

    # Check if IP is in the blacklist
    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return
    
      # Check for Nimda worm signature
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking Nimda source IP: {src_ip}")
        return

    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    # Import whitelist and blacklist IPs
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)