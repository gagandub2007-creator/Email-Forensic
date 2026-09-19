import pytest
from app.services.ip_intel import IPIntelEngine, MockIPIntelProvider

def test_ip_intel_mock_database():
    engine = IPIntelEngine()
    results = engine.analyze_ips(["185.220.101.5"])
    
    assert "185.220.101.5" in results
    intel = results["185.220.101.5"]
    assert intel["country"] == "Germany"
    assert intel["is_vpn_proxy_tor"] is True
    assert intel["network_type"] == "anonymization"
    assert intel["reputation"] == "Poor"
    assert intel["is_mock"] is True
    assert "Estimated infrastructure geolocation" in intel["caveat"]

def test_ip_intel_private_ip():
    engine = IPIntelEngine()
    results = engine.analyze_ips(["192.168.1.1"])
    
    intel = results["192.168.1.1"]
    assert intel["network_type"] == "private"
    assert intel["is_mock"] is True
    assert intel["reputation"] == "Neutral"

def test_ip_intel_fallback():
    engine = IPIntelEngine()
    results = engine.analyze_ips(["8.8.8.8"])
    
    intel = results["8.8.8.8"]
    assert intel["country"] != "Unknown" # Should hit the deterministic fallback
    assert intel["is_mock"] is True
    assert "Do not interpret as exact attacker location" in intel["caveat"]

def test_ip_intel_unique_ips():
    engine = IPIntelEngine()
    # Test that it processes duplicates fine
    results = engine.analyze_ips(["8.8.8.8", "8.8.8.8", "1.1.1.1"])
    
    assert len(results) == 2
    assert "8.8.8.8" in results
    assert "1.1.1.1" in results
