#!/usr/bin/env python3
"""Project Title: Network Discovery Listener

A CLI tool that captures live packets or parses pcap files to detect Layer 2 discovery protocols
(CDP, LLDP, EDP, FDP) and logs parsed details to an output file.

Author: Kris Armstrong
"""

from __future__ import annotations
import argparse
import logging
import sys
import time
from typing import Optional

from scapy.all import sniff, rdpcap, Raw
from scapy.contrib.lldp import LLDPDU
from scapy.layers.l2 import Dot3, SNAP

__version__ = "1.6.0"


def setup_logging(verbose: bool, logfile: Optional[str] = None) -> None:
    """Configure logging output to console and optional logfile."""
    logger = logging.getLogger()
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setLevel(level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)


def parse_and_log_packet(pkt, log_file: str) -> None:
    """Parse discovery protocol packets and append details to the log file."""
    try:
        with open(log_file, "a") as f:
            f.write(f"Time: {time.ctime()}\n")
            if pkt.haslayer(Dot3) and pkt.haslayer(SNAP):
                if pkt[Dot3].dst == "01:00:0c:cc:cc:cc" and pkt[SNAP].code == 0x2000:
                    proto = "CDP"
                elif pkt[Dot3].dst == "01:80:c2:00:00:0e" and pkt.haslayer(LLDPDU):
                    proto = "LLDP"
                elif pkt[Dot3].dst == "01:e0:52:cc:cc:cc":
                    proto = "EDP"
                elif pkt[Dot3].dst == "01:e0:2f:00:00:00":
                    proto = "FDP"
                else:
                    return
                f.write(f"Protocol: {proto}\n")
                f.write(f"Source MAC: {pkt[Dot3].src}\n")
                f.write(f"Destination MAC: {pkt[Dot3].dst}\n")
                if pkt.haslayer(Raw):
                    f.write(f"Payload (hex): {pkt[Raw].load.hex()}\n")
                f.write("="*50 + "\n")
                logging.debug("Logged %s packet from %s to %s", proto, pkt[Dot3].src, pkt[Dot3].dst)
    except Exception as e:
        logging.error("Error writing packet data: %s", e)


def live_capture(interface: str, log_file: str, daemon: bool) -> None:
    """Capture live packets on interface for discovery protocols."""
    if not daemon:
        logging.info("Listening on interface %s for discovery protocols...", interface)
    sniff(iface=interface, prn=lambda p: parse_and_log_packet(p, log_file), store=0)


def parse_pcap(input_file: str, log_file: str) -> None:
    """Parse a pcap file for discovery protocols and log parsed data."""
    logging.info("Reading from pcap file %s", input_file)
    packets = rdpcap(input_file)
    for pkt in packets:
        parse_and_log_packet(pkt, log_file)
    logging.info("Parsing complete. Output written to %s", log_file)


def main() -> None:
    """CLI entrypoint: parse arguments, configure logging, and run capture or parsing."""
    parser = argparse.ArgumentParser(description="Network Discovery Listener (CDP, LLDP, EDP, FDP)")
    parser.add_argument("-i", "--interface", help="Network interface for live capture")
    parser.add_argument("-f", "--file", help="PCAP file to parse")
    parser.add_argument("-o", "--output", default="discovery_protocol_log.txt", help="Parsed output file")
    parser.add_argument("--daemon", action="store_true", help="Quiet background mode")
    parser.add_argument("--logfile", help="Optional logfile for runtime logs")
    parser.add_argument("--verbose", action="store_true", help="Enable debug-level logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()
    setup_logging(args.verbose, args.logfile)

    if args.interface:
        live_capture(args.interface, args.output, args.daemon)
    elif args.file:
        parse_pcap(args.file, args.output)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Exiting on user interrupt")
        sys.exit(0)
    except Exception as e:
        logging.critical("Fatal error: %s", e)
        sys.exit(1)
