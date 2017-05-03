import re
import socket
import time
import argparse
import sys
import os
import ctypes


TRACEROUTE_PORT = 33434
WHOIS_HOST = "whois.iana.org"
WHOIS_PORT = 43
LOCAL_IP_PATTERN = "192\.168(\.\d{1,3}){2}|10(\.\d{1,3}){3}|172\.16(\.\d{1,3}){2}"


def get_whois_addr(ip_addr):
    res = whois_request(ip_addr)
    return re.findall("refer.*", res)[0].split()[1]


def is_local(ip_addr):
    return re.match(LOCAL_IP_PATTERN, ip_addr) is not None


def get_country_info(whois_response):
    if "address" not in whois_response:
        return ""
    addresses = re.findall("address.*", whois_response)
    final_result = ' '.join(addresses[-1].split()[1:])
    return "{} ".format(final_result)


def get_as_info(whois_response):
    if "origin" not in whois_response:
        return ""
    return re.findall("origin", whois_response)[0].split()[1].decode() + " "


def get_ip_info(ip_addr):
    if is_local(ip_addr):
        return "local "
    whois_response = whois_request(get_whois_addr(ip_addr))
    return "{}{}".format(
        get_as_info(whois_response),
        get_country_info(whois_response))


def whois_gen(url: str):
    with socket.create_connection((WHOIS_HOST, WHOIS_PORT)) as sock:
        sock.send(url.encode() + b"\r\n")
        data = b'0'
        while data:
            data = sock.recv(1024)
            yield data.decode()


def whois_request(url: str):
    return "".join(whois_gen(url))


def check_rights():
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if not is_admin:
        print("traceroute requires root rights")
        sys.exit(0)


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
    reciever.bind(("", TRACEROUTE_PORT))
    node_start_time = time.time()
    sender.sendto(b"a" * packet_size, (destination, TRACEROUTE_PORT))
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
            ip_info = ""
        else:
            ip_info = get_ip_info(hop_name)
    return ttl, hop_name, hop_addr, ip_info, (node_finish_time - node_start_time) * 1000, hop_addr == destination


def traceroute(target, max_hops=32, packet_size=60):
    try:
        destination = socket.gethostbyname(target)
    except socket.gaierror:
        print("{} is invalid".format(target))
        sys.exit(0)
    print("traceroute to {} ({}), {} hops max, {} byte packets".format(target, destination, max_hops, packet_size))
    for ttl in range(1, max_hops + 1):
        ping_result = ping_request(destination, ttl, packet_size)
        print(" {} {} ({}) {}{:0.2f} ms".format(*ping_result[:-1]))
        if ping_result[-1]:
            break


def main():
    check_rights()
    parser = argparse.ArgumentParser()
    parser.add_argument("target", action="store", help="target")
    parser.add_argument("-m", "--max-hops", type=int, action="store", default=32)
    args = vars(parser.parse_args(sys.argv[1:]))
    traceroute(args["target"], args["max_hops"])


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\ntraceroute was interrupted by user")
