def test_version():
    import aruba_ssid_configurator as mod
    assert hasattr(mod, "__version__")
    assert isinstance(mod.__version__, str)
