import pytest
import network_discovery_listener as mdl

def test_version():
    assert hasattr(mdl, "__version__")
    assert isinstance(mdl.__version__, str)
