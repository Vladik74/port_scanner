from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_TCP_port(address: str, port, timeout) -> (bool, float, int, str, str):
    sport = RandShort()
    main_package = IP(dst=address) / TCP(sport=sport, dport=port, flags="S")
    main_r = sr1(main_package, timeout=timeout, verbose=False)
    deltatime = 0
    opened_protocol = None
    if main_r is None:
        is_closed = True
    else:
        is_closed = False
        deltatime = main_r.time - main_package.sent_time
        flags = main_r.getlayer(TCP).flags
        send(IP(dst=address) / TCP(sport=sport, dport=port, flags="A"),
             verbose=False)
        dns_package = (
                IP(dst=address) / TCP(sport=sport, dport=port, flags="A") /
                DNS(rd=1, qd=DNSQR(qname=f"{address}")))
        dns_r = sr1(dns_package, verbose=False, timeout=timeout)
        http_package = (IP(dst=address) /
                        TCP(sport=sport, dport=port, flags="A")
                        / 'GET / HTTP/1.1\r\nHost: f"{address}"\r\n\r\n')
        http_r = sr1(http_package, verbose=False, timeout=timeout)
        other_http_t = sr(http_package, verbose=False, timeout=timeout)
        if flags == SYNACK:
            send(IP(dst=address) / TCP(sport=sport, dport=port, flags="R"),
                 verbose=False)
        if dns_r is not None:
            opened_protocol = 'DNS'
            deltatime = dns_r.time - dns_package.sent_time
        elif other_http_t is not None:
            opened_protocol = 'HTTP'
            # deltatime = http_r.time - http_package.sent_time
    return is_closed, deltatime, port, 'TCP', opened_protocol


def check_UDP_port(address: str, port, timeout) -> (bool, float, int, str, str):
    is_closed = True
    opened_protocol = None
    sport = RandShort()
    echo_package = IP(dst=address) / UDP(sport=sport, dport=port) / ICMP()
    echo_r = sr1(echo_package, verbose=False, timeout=timeout)
    dns_package = (IP(dst=address) / UDP(sport=sport, dport=port) /
                   DNS(rd=1, qd=DNSQR(qname=address)))
    dns_r = sr1(dns_package, verbose=False, timeout=timeout)
    deltatime = 0
    if echo_r is not None:
        is_closed = False
        opened_protocol = 'ECHO'
        deltatime = echo_r.time - echo_package.sent_time
    elif dns_r is not None:
        is_closed = False
        opened_protocol = 'DNS'
        deltatime = dns_r.time - dns_package.sent_time
    # print(port, package)

    return is_closed, deltatime, port, 'UDP', opened_protocol


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip')
    parser.add_argument('--timeout', default=2, type=int)
    parser.add_argument('-j', '--num-threads', default=1, type=int)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-g', '--guess', action='store_true')
    parser.add_argument('range', nargs='*')
    return parser.parse_args()


def print_answer(is_closed, time, port, protocol, opened_protocol, args):
    if is_closed:
        return
    if opened_protocol is None:
        opened_protocol = ""
    if args.verbose and args.guess:
        print(protocol, port, time, opened_protocol)
    elif not args.verbose and not args.guess:
        print(protocol, port)
    elif args.verbose and not args.guess:
        print(protocol, port, time)
    elif not args.verbose and args.guess:
        print(protocol, port, opened_protocol)


SYNACK = 0x12
start_port = 50
end_port = 60
closed = []
opened = []
args = parse()
for i in args.range:
    protocol, r = i.split('/')
    nums = r.split(',')
    # print(protocol, nums)
    tcp_ports = []
    udp_ports = []
    for n in nums:
        d = n.split('-')
        if len(d) == 1:
            if protocol == 'udp':
                udp_ports.append(int(d[0]))
            if protocol == 'tcp':
                tcp_ports.append(int(d[0]))
        else:
            if protocol == 'udp':
                udp_ports.extend(range(int(d[0]), int(d[1]) + 1))
            if protocol == 'tcp':
                tcp_ports.extend(range(int(d[0]), int(d[1]) + 1))
    tasks = []
    with ThreadPoolExecutor(max_workers=args.num_threads) as tpe:
        for i in udp_ports:
            tasks.append(tpe.submit(check_UDP_port, args.ip, i, args.timeout))
        for j in tcp_ports:
            tasks.append(tpe.submit(check_TCP_port, args.ip, j, args.timeout))

        for task in as_completed(tasks):
            print_answer(*task.result(), args)
