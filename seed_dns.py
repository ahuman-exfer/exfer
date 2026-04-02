#!/usr/bin/env python3
"""
Lightweight DNS responder for seed.exfer.org.
Serves A records from the crawler's healthy_nodes.txt.
Returns a random subset of up to 8 healthy IPs per query.

Usage:
    python3 seed_dns.py [--port 5353] [--nodes healthy_nodes.txt]

Bind to port 53 for production (requires root or CAP_NET_BIND_SERVICE).
"""

import socket
import struct
import random
import time
import argparse
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("dns")

MAX_ANSWERS = 8
TTL = 60  # seconds
RELOAD_INTERVAL = 30  # re-read file every 30s


def load_healthy_nodes(path):
    """Load healthy IPs from crawler output file."""
    try:
        ips = []
        for line in Path(path).read_text().strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                ips.append(line)
        return ips
    except Exception as e:
        log.warning("Failed to load %s: %s", path, e)
        return []


def build_dns_response(query_data, ips):
    """Build a minimal DNS A record response."""
    if len(query_data) < 12:
        return None

    # Parse query header
    txn_id = query_data[:2]
    # Parse question section to echo it back
    # Skip header (12 bytes), read QNAME
    pos = 12
    qname_start = pos
    while pos < len(query_data) and query_data[pos] != 0:
        pos += 1 + query_data[pos]
    pos += 1  # null terminator
    if pos + 4 > len(query_data):
        return None
    qname = query_data[qname_start:pos]
    qtype = struct.unpack("!H", query_data[pos : pos + 2])[0]
    qclass = struct.unpack("!H", query_data[pos + 2 : pos + 4])[0]

    # Only respond to A record queries (type 1, class IN=1)
    if qtype != 1 or qclass != 1:
        return None

    # Select random subset
    selected = random.sample(ips, min(MAX_ANSWERS, len(ips))) if ips else []

    # Build response
    flags = 0x8180  # Response, Authoritative, Recursion available
    resp = txn_id
    resp += struct.pack("!H", flags)
    resp += struct.pack("!H", 1)  # QDCOUNT
    resp += struct.pack("!H", len(selected))  # ANCOUNT
    resp += struct.pack("!H", 0)  # NSCOUNT
    resp += struct.pack("!H", 0)  # ARCOUNT

    # Question section (echo)
    resp += qname
    resp += struct.pack("!HH", qtype, qclass)

    # Answer section
    for ip in selected:
        # Name pointer to question
        resp += b"\xc0\x0c"
        resp += struct.pack("!H", 1)  # TYPE A
        resp += struct.pack("!H", 1)  # CLASS IN
        resp += struct.pack("!I", TTL)
        resp += struct.pack("!H", 4)  # RDLENGTH
        resp += socket.inet_aton(ip)

    return resp


def main():
    parser = argparse.ArgumentParser(description="Exfer seed DNS responder")
    parser.add_argument("--port", type=int, default=53, help="UDP port to listen on")
    parser.add_argument(
        "--nodes", default="healthy_nodes.txt", help="Healthy nodes file from crawler"
    )
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.settimeout(RELOAD_INTERVAL)

    log.info("DNS responder listening on %s:%d", args.bind, args.port)

    healthy_ips = load_healthy_nodes(args.nodes)
    last_reload = time.time()
    queries_served = 0

    while True:
        # Reload node list periodically
        if time.time() - last_reload > RELOAD_INTERVAL:
            healthy_ips = load_healthy_nodes(args.nodes)
            last_reload = time.time()
            if queries_served > 0:
                log.info(
                    "Reloaded %d healthy nodes (%d queries served)",
                    len(healthy_ips),
                    queries_served,
                )

        try:
            data, addr = sock.recvfrom(512)
        except socket.timeout:
            continue
        except Exception as e:
            log.warning("recv error: %s", e)
            continue

        response = build_dns_response(data, healthy_ips)
        if response:
            try:
                sock.sendto(response, addr)
                queries_served += 1
            except Exception as e:
                log.warning("send error: %s", e)


if __name__ == "__main__":
    main()
