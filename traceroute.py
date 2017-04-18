import socket
import time
import argparse


PORT = 33434


def gethostbyaddr(ip_addr):
    try:
        name = socket.gethostbyaddr(ip_addr)
        return name
    except socket.herror:
        return None


def ping_request(destination, ttl, packet_size):
    node_finish_time = None
    reciever = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    reciever.settimeout(1)
    reciever.bind(("", PORT))
    node_start_time = time.time()
    sender.sendto(b"a" * packet_size, (destination, PORT))
    hop_addr = None
    hop_name = None
    try:
        packet, curr_addr = reciever.recvfrom(512)
        node_finish_time = time.time()
        hop_addr = curr_addr[0]
        hop_name = gethostbyaddr(hop_addr)
        hop_name = hop_addr if hop_name is None else hop_name[0]
    except socket.timeout:
        node_finish_time = time.time()
    finally:
        sender.close()
        reciever.close()
        if node_finish_time is None:
            node_finish_time = time.time()
        if hop_name is None:
            hop_name = " * "
            hop_addr = " * "
    return ttl, hop_name, hop_addr, (node_finish_time - node_start_time) * 1000, hop_addr == destination


def traceroute(target, max_hops=32, packet_size=60):
    destination = socket.gethostbyname(target)
    print("traceroute to {} ({}), {} hops max, {} byte packets".format(target, destination, max_hops, packet_size))
    for ttl in range(1, max_hops + 1):
        ping_result = ping_request(destination, ttl, packet_size)
        print(" {} {} ({}) {:0.2f} ms".format(*ping_result[:-1]))
        if ping_result[-1]:
            break


if __name__ == '__main__':
    traceroute("google-public-dns-a.google.com", 30)
