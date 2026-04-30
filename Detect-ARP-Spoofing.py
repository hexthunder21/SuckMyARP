import subprocess
import ipaddress
import schedule 
import time
from collections import defaultdict

# Create the file where it will contain IP and MAC addresses
def gain_arp_file():
    command = "ip neigh > arp-table.txt"
    subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )

def parse_line(line):
    array = line.split()
    if not array:
        return None
    
    data = []
    # get an IP address
    if ipaddress.ip_address(array[0]):
            data.append(array[0])
    for index, word in enumerate(array):
        # get an interface
        if word == "dev":
            data.append(array[index+1])
        #get a MAC address
        if word == "lladdr":
            data.append(array[index+1])
            break

    # here I check if I have an interface and MAC, because it is not always there is 
    return data if len(data) == 3 else None

def parse_table(array):
    table = defaultdict(lambda: defaultdict(list))
    # parsing every line in exists array
    for i in range(len(array)):
        line = parse_line(line=array[i])
        if line is None:
            continue
        ip, iface, mac = line
        table[iface][ip].append(mac)
    
    # convert defaultdict to dict and return it
    result = {iface: dict(ips) for iface, ips in table.items()}
    return result

# main validation func checks if any IP had more than 1 MAC 
def validate_arp_table(notValidatedTable):
    clearTable = parse_table(notValidatedTable)
    for Keys in clearTable.keys():
        for internalKeys in clearTable[Keys].keys():
            if len(clearTable[Keys][internalKeys]) > 1:
                print(f"""{'-' * 40}
[!] Possible ARP Spoofing attack. Check your LAN!
The Strange object is below
{internalKeys} has more than 1 MAC: {clearTable[Keys][internalKeys]}
{'-' * 40}""")

def main():
    gain_arp_file()

    # Read that file and parse it -> create corelation IP and MAC
    with open("arp-table.txt", 'r') as file:
        content = file.read()
        arpt = content.split('\n')

    # Set up schedule for scan arp table every 5 minutes
    schedule.every(5).minutes.do(validate_arp_table, arpt)
    while True:
        schedule.run_pending()
        time.sleep(1)

main()

