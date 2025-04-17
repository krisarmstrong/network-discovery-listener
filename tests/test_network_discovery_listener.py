#!/usr/bin/env python3
"""
Project Title: NetworkDiscoveryListenerTests

Pytest smoke tests for network_discovery_listener.py functionality.

Author: Kris Armstrong
"""
__version__ = "1.0.0"

import pytest
import subprocess
from pathlib import Path
import network_discovery_listener

@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for testing.

    Args:
        tmp_path: Pytest-provided temporary path.

    Returns:
        Path to temporary directory.
    """
    return tmp_dir

def test_setup_logging(temp_dir: Path) -> None:
    """Test logging configuration."""
    log_file = temp_dir / "test.log"
    network_discovery_listener.setup_logging(verbose=True, logfile=str(log_file))
    assert log_file.exists()
    logging.info("Test log entry")
    with log_file.open("r") as f:
        assert "Test log entry" in f.read()

def test_check_sensitive_data(temp_dir: Path) -> None:
    """Test sensitive data detection."""
    log_file = temp_dir / "output.txt"
    clean_content = "Time: test\nProtocol: CDP\nSource MAC: 00:11:22:33:44:55"
    sensitive_content = "api_key=secret123"
    assert network_discovery_listener.check_sensitive_data(str(log_file), clean_content)
    assert not network_discovery_listener.check_sensitive_data(str(log_file), sensitive_content)

def test_version_bumper_generation(temp_dir: Path) -> None:
    """Test version_bumper.py generation."""
    from git_setup import VERSION_BUMPER_TEMPLATE, create_file
    create_file(temp_dir / 'version_bumper.py', VERSION_BUMPER_TEMPLATE)
    assert (temp_dir / 'version_bumper.py').exists()
    result = subprocess.run(['python', 'version_bumper.py', '--help'], cwd=temp_dir, capture_output=True, text=True)
    assert result.returncode == 0