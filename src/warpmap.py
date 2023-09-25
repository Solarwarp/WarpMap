from scapy.all import ARP, Ether, srp
import socket
import os

print("""

   _       __                 __  ___          
  | |     / /___ __________  /  |/  /___ _____ 
  | | /| / / __ `/ ___/ __ \/ /|_/ / __ `/ __ \
  | |/ |/ / /_/ / /  / /_/ / /  / / /_/ / /_/ /
  |__/|__/\__,_/_/  / .___/_/  /_/\__,_/ .___/ 
                   /_/                /_/      
        
                By: SolarWarp
""")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

def get_network_range(ip_addr):
    ip_parts = ip_addr.split(".")
    return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1/24"

def scan(ip):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip)
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=False)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def nmap_scan(ip, scan_type):
    command = f"nmap {scan_type} {ip}"
    process = os.popen(command)
    results = str(process.read())
    return results

local_ip = get_local_ip()
network = get_network_range(local_ip)
devices = scan(network)

print("Available devices in the network:")
print("IP Address\t\tMAC Address")
print("-----------------------------------------")

# Ask user for the type of scan they want
print("""
Choose the type of nmap scan:
1. Ping Scan (-sP)
2. SYN Scan (-sS)
3. Connect Scan (-sT)
4. UDP Scan (-sU)
5. Version Detection (-sV)
""")
scan_choice = input("Enter your choice (1-5): ")

if scan_choice == '1':
    scan_type = "-sP"
elif scan_choice == '2':
    scan_type = "-sS"
elif scan_choice == '3':
    scan_type = "-sT"
elif scan_choice == '4':
    scan_type = "-sU"
elif scan_choice == '5':
    scan_type = "-sV"
else:
    print("Invalid choice!")
    exit(0)

for device in devices:
    print(device['ip'] + "\t\t" + device['mac'])

    # Perform nmap scan on the device
    print("Nmap scan results for " + device['ip'] + ":")
    print(nmap_scan(device['ip'], scan_type))
    print("-----------------------------------------")
