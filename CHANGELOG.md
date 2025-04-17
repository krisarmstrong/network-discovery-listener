# Changelog

## [1.6.1] - 2025-04-18
- network_discovery_listener.py: Added rotating log handler, sensitive data checks, enhanced type annotations
- tests/test_network_discovery_listener.py: Added tests for logging and sensitive data checks
- Standardized naming to NetworkDiscoveryListener
- Updated README.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md
- Added .gitignore and requirements.txt

## [1.6.0] - 2025-04-18
- Refactored to network_discovery_listener.py with enhanced header and author
- Added CLI --logfile handling and --version flag
- Structured logging (console + optional file) and debug messages
- Full type annotations and robust error handling
- Added pytest scaffold and version_bumper.py

## [1.5.0]
- Initial structured logging and daemon mode