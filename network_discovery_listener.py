#!/usr/bin/env python3
"""
Project Title: NetworkDiscoveryListener

A CLI tool to capture live packets or parse PCAP files for Layer 2 discovery protocols (CDP, LLDP, EDP, FDP) and log parsed details to an output file.

Author: Kris Armstrong
"""
__version__ = "1.6.1"

import argparse
import logging
from logging.handlers import RotatingFileHandler
import sys
import time
import re
from typing import Optional
from scapy.all import sniff, rdpcap, Packet, Raw
from scapy.contrib.lldp import LLDPDU
from scapy.layers.l2 import Dot3, SNAP

def setup_logging(verbose: bool, logfile: Optional[str] = None) -> None:
    """Configure logging with console and rotating file handler.

    Args:
        verbose: Enable DEBUG level logging to console if True.
        logfile: Path to log file, defaults to network_discovery_listener.log if unspecified.

    Returns:
        None
    """
    logger = logging.getLogger()
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logfile = logfile or "network_discovery_listener.log"
    file_handler = RotatingFileHandler(logfile, maxBytes=10_000_000, backupCount=5)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

def check_sensitive_data(log_file: str, content: str) -> bool:
    """Check for sensitive data in the log output.

    Args:
        log_file: Path to the log file.
        content: Content to check.

    Returns:
        True if no sensitive data found, False otherwise.
    """
    sensitive_patterns = [r'api_key\s*=\s*["\'].+["\']', r'password\s*=\s*["\'].+["\']']
    for pattern in sensitive_patterns:
        if re.search(pattern, content):
            logging.warning(f"Potential sensitive data found in {log_file}")
            return False
    return True

def parse_and_log_packet(pkt: Packet, log_file: str) -> None:
    """Parse discovery protocol packets and append details to the log file.

    Args:
        pkt: Scapy packet to parse.
        log_file: Output file for parsed data.

    Returns:
        None
    """
    try:
        log_content = f"Time: {time.ctime()}\n"
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
            log_content += f"Protocol: {proto}\n"
            log_content += f"Source MAC: {pkt[Dot3].src}\n"
            log_content += f"Destination MAC: {pkt[Dot3].dst}\n"
            if pkt.haslayer(Raw):
                log_content += f"Payload (hex): {pkt[Raw].load.hex()}\n"
            log_content += "="*50 + "\n"

            if not check_sensitive_data(log_file, log_content):
                logging.error("Aborted logging due to potential sensitive data")
                return

            with open(log_file, "a", encoding="utf-8") as f:
                f.write(log_content)
            logging.debug("Logged %s packet from %s to %s", proto, pkt[Dot3].src, pkt[Dot3].dst)
    except Exception as e:
        logging.error("Error writing packet data: %s", e)

def live_capture(interface: str, log_file: str, daemon: bool) -> None:
    """Capture live packets on interface for discovery protocols.

    Args:
        interface: Network interface to capture on.
        log_file: Output file for parsed data.
        daemon: Run in quiet background mode if True.

    Returns:
        None
    """
    if not daemon:
        logging.info("Listening on interface %s for discovery protocols...", interface)
    sniff(iface=interface, prn=lambda p: parse_and_log_packet(p, log_file), store=0)

def parse_pcap(input_file: str, log_file: str) -> None:
    """Parse a PCAP file for discovery protocols and log parsed data.

    Args:
        input_file: Path to PCAP file.
        log_file: Output file for parsed data.

    Returns:
        None
    """
    logging.info("Reading from PCAP file %s", input_file)
    try:
        packets = rdpcap(input_file)
        for pkt in packets:
            parse_and_log_packet(pkt, log_file)
        logging.info("Parsing complete. Output written to %s", log_file)
    except Exception as e:
        logging.error("Error parsing PCAP file: %s", e)
        sys.exit(1)

def main() -> None:
    """CLI entrypoint: parse arguments, configure logging, and run capture or parsing."""
    parser = argparse.ArgumentParser(
        description="Network Discovery Listener (CDP, LLDP, EDP, FDP)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface for live capture"
    )
    parser.add_argument(
        "-f", "--input_file",
        help="PCAP file to parse"
    )
    parser.add_argument(
        "-o", "--output_file",
        default="discovery_protocol_log.txt",
        help="Output file for parsed data"
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run in quiet background mode"
    )
    parser.add_argument(
        "--logfile",
        help="Log file for runtime logs"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug-level logging"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args()
    setup_logging(args.verbose, args.logfile)

    if args.interface and args.input_file:
        logging.error("Cannot specify both interface and input file")
        sys.exit(1)
    if not (args.interface or args.input_file):
        parser.print_help()
        sys.exit(1)

    try:
        if args.interface:
            live_capture(args.interface, args.output_file, args.daemon)
        else:
            parse_pcap(args.input_file, args.output_file)
    except KeyboardInterrupt:
        logging.info("Cancelled by user")
        sys.exit(0)
    except Exception as e:
        logging.critical("Fatal error: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()