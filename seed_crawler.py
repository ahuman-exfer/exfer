#!/usr/bin/env python3
"""
Exfer seed crawler. Probes known nodes every 10 minutes, tracks which are
healthy (reachable, synced), and writes the healthy list to a file.

Usage:
    python3 seed_crawler.py [--out healthy_nodes.txt] [--interval 600]

The crawler discovers new peers by requesting addr lists from healthy nodes.
"""

import socket
import struct
import os
import sys
import time
import json
import hashlib
import argparse
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("crawler")

# ── Protocol constants ──

PROTOCOL_VERSION = 5
GENESIS_ID = bytes.fromhex(
    "d7b6805c8fd793703db88102b5aed2600af510b79e3cb340ca72c1f762d1e051"
)
PORT = 9333
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
MAX_HEIGHT_LAG = 100  # nodes within 100 blocks of best are "synced"

# Message types
MSG_HELLO = 0x01
MSG_GET_TIP = 0x13
MSG_TIP_RESPONSE = 0x14
MSG_GET_ADDR = 0x16
MSG_ADDR = 0x17

# Hello payload: version(4) + genesis(32) + height(8) + best_id(32) +
# cumulative_work(32) + nonce(32) + echo(32) + pubkey(32) + sig(64) = 268
HELLO_SIZE = 268

# Bootstrap seeds
SEEDS = [
    "80.78.31.82",
    "82.221.100.201",
    "89.127.232.155",
]


def build_hello():
    """Build a minimal Hello message for probing."""
    payload = struct.pack("<I", PROTOCOL_VERSION)
    payload += GENESIS_ID  # genesis_block_id (32)
    payload += struct.pack("<Q", 0)  # best_height (8)
    payload += b"\x00" * 32  # best_block_id (32)
    payload += b"\x00" * 32  # cumulative_work (32)
    payload += os.urandom(32)  # nonce (32)
    payload += b"\x00" * 32  # echo (32) — filled after receiving peer's nonce
    payload += b"\x00" * 32  # pubkey (32) — dummy
    payload += b"\x00" * 64  # sig (64) — dummy
    # Wire frame: msg_type(1) + payload_len(4 LE) + payload
    frame = struct.pack("<BI", MSG_HELLO, len(payload)) + payload
    return frame


def read_frame(sock):
    """Read one wire frame: msg_type(1) + length(4 LE) + payload."""
    header = b""
    while len(header) < 5:
        chunk = sock.recv(5 - len(header))
        if not chunk:
            return None, None
        header += chunk
    msg_type = header[0]
    length = struct.unpack_from("<I", header, 1)[0]
    if length > 8_388_608:  # MAX_MESSAGE_SIZE
        return None, None
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(min(length - len(payload), 65536))
        if not chunk:
            return None, None
        payload += chunk
    return msg_type, payload


def parse_hello(payload):
    """Extract height and version from Hello payload."""
    if len(payload) < 108:
        return None
    version = struct.unpack_from("<I", payload, 0)[0]
    genesis = payload[4:36]
    height = struct.unpack_from("<Q", payload, 36)[0]
    return {"version": version, "genesis": genesis, "height": height}


def parse_addr(payload):
    """Parse Addr message: count(u16 LE) + entries[]. Each entry = 18 bytes addr + 8 bytes last_seen = 26."""
    if len(payload) < 2:
        return []
    count = struct.unpack_from("<H", payload, 0)[0]
    addrs = []
    pos = 2
    for _ in range(count):
        if pos + 26 > len(payload):
            break
        # 16 bytes IPv6/mapped-v4 + 2 bytes port LE
        ip_bytes = payload[pos : pos + 16]
        port = struct.unpack_from("<H", payload, pos + 16)[0]
        pos += 26  # 18 + 8 (last_seen)
        # Convert IPv4-mapped IPv6 to IPv4
        if ip_bytes[:12] == b"\x00" * 10 + b"\xff\xff":
            ip = socket.inet_ntoa(ip_bytes[12:16])
        else:
            try:
                ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
            except Exception:
                continue
        if port == PORT and ip not in ("0.0.0.0", "127.0.0.1"):
            addrs.append(ip)
    return addrs


def probe_node(ip):
    """
    Connect to a node, exchange Hello, get their height.
    Returns (height, [discovered_ips]) or (None, []) on failure.
    """
    discovered = []
    try:
        sock = socket.create_connection((ip, PORT), timeout=CONNECT_TIMEOUT)
        sock.settimeout(READ_TIMEOUT)

        # Send our Hello
        sock.sendall(build_hello())

        # Read their Hello
        msg_type, payload = read_frame(sock)
        if msg_type != MSG_HELLO or payload is None:
            sock.close()
            return None, []

        info = parse_hello(payload)
        if info is None or info["genesis"] != GENESIS_ID:
            sock.close()
            return None, []

        height = info["height"]

        # Try to get addr list (best effort — connection may drop)
        try:
            get_addr_frame = struct.pack("<BI", MSG_GET_ADDR, 0)
            sock.sendall(get_addr_frame)

            # Read responses for a short time
            sock.settimeout(3)
            deadline = time.time() + 3
            while time.time() < deadline:
                mt, pl = read_frame(sock)
                if mt is None:
                    break
                if mt == MSG_ADDR and pl:
                    discovered = parse_addr(pl)
                    break
        except Exception:
            pass

        sock.close()
        return height, discovered

    except Exception:
        return None, []


def run_crawl(known_ips):
    """Probe all known IPs in parallel, return healthy list and discovered peers."""
    best_height = 0
    results = {}
    all_discovered = set()

    log.info("Probing %d nodes...", len(known_ips))

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(probe_node, ip): ip for ip in known_ips}
        for future in as_completed(futures, timeout=30):
            ip = futures[future]
            try:
                height, discovered = future.result(timeout=15)
                if height is not None:
                    results[ip] = height
                    if height > best_height:
                        best_height = height
                    for d in discovered:
                        all_discovered.add(d)
            except Exception:
                pass

    # Healthy = reachable + within MAX_HEIGHT_LAG of best
    healthy = []
    for ip, height in results.items():
        if best_height - height <= MAX_HEIGHT_LAG:
            healthy.append(ip)

    log.info(
        "Probed %d, reachable %d, healthy %d (best height: %d)",
        len(known_ips),
        len(results),
        len(healthy),
        best_height,
    )

    # Log stragglers
    for ip, height in sorted(results.items(), key=lambda x: -x[1]):
        lag = best_height - height
        status = "OK" if lag <= MAX_HEIGHT_LAG else "BEHIND(%d)" % lag
        log.debug("  %s  height=%d  %s", ip, height, status)

    return healthy, all_discovered, best_height


def main():
    parser = argparse.ArgumentParser(description="Exfer seed crawler")
    parser.add_argument(
        "--out",
        default="healthy_nodes.txt",
        help="Output file for healthy node list",
    )
    parser.add_argument(
        "--interval", type=int, default=600, help="Crawl interval in seconds"
    )
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument(
        "--seeds-file", help="File with additional seed IPs (one per line)"
    )
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Start with seeds + any previously known healthy nodes
    known_ips = set(SEEDS)
    out_path = Path(args.out)
    if out_path.exists():
        for line in out_path.read_text().strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                known_ips.add(line)
    if args.seeds_file and Path(args.seeds_file).exists():
        for line in Path(args.seeds_file).read_text().strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                known_ips.add(line)

    while True:
        healthy, discovered, best_height = run_crawl(known_ips)

        # Add discovered peers for next round
        known_ips.update(discovered)
        known_ips.update(healthy)

        # Write healthy list
        with open(out_path, "w") as f:
            f.write("# Exfer healthy nodes — updated %s\n" % time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
            f.write("# Best height: %d\n" % best_height)
            f.write("# Healthy: %d / %d known\n" % (len(healthy), len(known_ips)))
            for ip in sorted(healthy):
                f.write("%s\n" % ip)

        log.info(
            "Wrote %d healthy nodes to %s (known: %d)",
            len(healthy),
            out_path,
            len(known_ips),
        )

        if args.once:
            break

        log.info("Next crawl in %ds", args.interval)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
