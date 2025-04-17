# Network Discovery Listener

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![PyPI](https://img.shields.io/pypi/v/network-discovery-listener)]() [![Python](https://img.shields.io/pypi/pyversions/network-discovery-listener)]()

A CLI utility to capture live packets or parse PCAP files for Layer 2 discovery protocols (CDP, LLDP, EDP, FDP) and log parsed packet details to a file.

## Requirements
- Python 3.9+
- scapy>=2.4.5, scapy_contrib

## Installation
```bash
pip install scapy scapy_contrib
```

## Usage
```bash
python network_discovery_listener.py --interface eth0 --output log.txt --verbose --logfile runtime.log
python network_discovery_listener.py --file capture.pcap --output parsed.txt
```

## Badges
- Build Status (CI)
- Coverage
- PyPI Version
- License
- Python Versions

## License
MIT License. See [LICENSE](LICENSE) for details.
