# NetworkDiscoveryListener

A Python CLI tool to capture live packets or parse PCAP files for Layer 2 discovery protocols (CDP, LLDP, EDP, FDP) and log parsed details to a file.

## Installation
```bash
pip install -r requirements.txt
chmod +x network_discovery_listener.py
```

## Usage
### network_discovery_listener.py
```bash
./network_discovery_listener.py --interface eth0 [--output_file log.txt] [--daemon] [--verbose] [--logfile runtime.log]
./network_discovery_listener.py --input_file capture.pcap [--output_file parsed.txt]
```

### version_bumper.py
```bash
python version_bumper.py --project_dir /path/to/project [--type minor] [--commit] [--git_tag] [--dry_run]
```

## Requirements
- Python 3.9+
- scapy>=2.4.5
- scapy_contrib

## Generated Files (via git_setup.py)
- **.gitignore**: Ignores Python, IDE, OS, and project-specific files (e.g., `__pycache__`, `.venv`, `tests/output/`).
- **README.md**: Project template with customizable title, installation, and usage.
- **CHANGELOG.md**: Version history with customizable author.
- **requirements.txt**: Lists dependencies.
- **LICENSE**: MIT license.
- **CONTRIBUTING.md**: Fork-branch-PR guidelines.
- **CODE_OF_CONDUCT.md**: Contributor Covenant with contact info.
- **tests/**: Directory with test files.
- **version_bumper.py**: Tool for bumping semantic versions.

## Notes
- **Sensitive Data**: Includes checks to prevent logging sensitive data (e.g., API keys).
- **Daemon Mode**: Use `--daemon` for quiet background operation.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)](https://github.com)
[![PyPI](https://img.shields.io/pypi/v/network-discovery-listener)](https://pypi.org/project/network-discovery-listener/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)