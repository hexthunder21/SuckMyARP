from scapy.all import *
from scapy.layers.l2 import Ether, ARP

new_MAC = "1d:41:ds:g2:ss:31"

def modify_mac_inPacket(pkt):
    if pkt.haslayer(Ether):
        print(f"Original: {pkt[Ether].src} -> {pkt[Ether].dst}")

        pkt[Ether].src = new_MAC

        del pkt[Ether].chksum
        if pkt.haslayer("IP"):
            del pkt["IP"].chksum

        print(f"Modified: {pkt[Ether].src} -> {pkt[Ether].dst}")
        sendp(pkt, verbose=False)














































# Functions:

# socket() -- create a new socket object
# socketpair() -- create a pair of new socket objects [] fromfd() -- create a socket object from an open file descriptor []
# send_fds() -- Send file descriptor to the socket.
# recv_fds() -- Receive file descriptors from the socket.
# fromshare() -- create a socket object from data received from socket.share() [*]
# gethostname() -- return the current hostname
# gethostbyname() -- map a hostname to its IP number
# gethostbyaddr() -- map an IP number or hostname to DNS info
# getservbyname() -- map a service name and a protocol name to a port number
# getprotobyname() -- map a protocol name (e.g. 'tcp') to a number
# ntohs(), ntohl() -- convert 16, 32 bit int from network to host byte order
# htons(), htonl() -- convert 16, 32 bit int from host to network byte order
# inet_aton() -- convert IP addr string (123.45.67.89) to 32-bit packed format
# inet_ntoa() -- convert 32-bit packed format IP to string (123.45.67.89)
# socket.getdefaulttimeout() -- get the default timeout value
# socket.setdefaulttimeout() -- set the default timeout value
# create_connection() -- connects to an address, with an optional timeout and
#                        optional source address.
# create_server() -- create a TCP socket and bind it to a specified address.

# [*] not available on all platforms!

# Special objects:

# SocketType -- type object for socket objects
# error -- exception raised for I/O errors
# has_ipv6 -- boolean value indicating if IPv6 is supported

# IntEnum constants:

# AF_INET, AF_UNIX -- socket domains (first argument to socket() call)
# SOCK_STREAM, SOCK_DGRAM, SOCK_RAW -- socket types (second argument)

# Integer constants:

# Many other constants may be defined; these may be used in calls to
# the setsockopt() and getsockopt() methods