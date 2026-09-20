import pytest
from app.services.url_intel import URLIntelEngine, DefaultDomainIntelProvider

def test_normal_domain():
    engine = URLIntelEngine()
    urls = ["https://example.com/path?q=1"]
    results = engine.analyze_urls(urls)
    
    assert len(results) == 1
    res = results[0]
    assert res["domain"] == "example.com"
    assert not res["is_suspicious"]
    assert not res["is_typosquatted"]
    assert res["reputation_score"] == 100.0
    
    # URL details
    assert res["url_details"]["protocol"] == "https"
    assert res["url_details"]["path"] == "/path"
    assert "q" in res["url_details"]["query_parameters"]
    assert res["url_details"]["redirect_indicators"] is False
    
    # Domain intel fallback
    assert res["domain_intel"]["registrar"] == "Unavailable"

def test_lookalike_typosquatting():
    engine = URLIntelEngine()
    urls = ["http://paypa1.com/login"]
    results = engine.analyze_urls(urls)
    
    res = results[0]
    assert res["is_suspicious"]
    assert res["is_typosquatted"]
    assert res["lookalike_intel"]["matched_brand"] == "paypal"
    assert res["lookalike_intel"]["distance"] == 1

def test_lookalike_character_substitution():
    engine = URLIntelEngine()
    # rnicrosoft -> microsoft (rn -> m)
    urls = ["https://rnicrosoft.com/login"]
    results = engine.analyze_urls(urls)
    
    res = results[0]
    assert res["is_suspicious"]
    assert res["is_typosquatted"]
    assert res["lookalike_intel"]["matched_brand"] == "microsoft"

def test_malicious_subdomain_brand_impersonation():
    engine = URLIntelEngine()
    urls = ["https://login.paypal.com.evil.xyz/auth"]
    results = engine.analyze_urls(urls)
    
    res = results[0]
    assert res["is_suspicious"]
    assert res["is_typosquatted"]
    assert "paypal" in res["lookalike_intel"]["reason"]

def test_redirect_indicators():
    engine = URLIntelEngine()
    urls = ["https://safe.com/auth?next=http://evil.com"]
    results = engine.analyze_urls(urls)
    
    res = results[0]
    assert res["url_details"]["redirect_indicators"] is True

def test_malformed_url():
    engine = URLIntelEngine()
    urls = ["not-a-valid-url-format"]
    results = engine.analyze_urls(urls)
    
    res = results[0]
    assert res["domain"] == "not-a-valid-url-format"
