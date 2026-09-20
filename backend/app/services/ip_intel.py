from abc import ABC, abstractmethod
from typing import Dict, Any, List
import ipaddress
import random

class IPIntelProvider(ABC):
    @abstractmethod
    def get_ip_intel(self, ip_address: str) -> Dict[str, Any]:
        """Fetch intelligence for a given IP address."""
        pass

class MockIPIntelProvider(IPIntelProvider):
    # Known public IP mock ranges or IP intelligence lookups for offline/demo robustness
    MOCK_GEO_DATABASE = {
        "185.220.101.5": {"country": "Germany", "region": "Hesse", "city": "Frankfurt", "isp": "Tor Exit Node Network", "asn": "AS208294", "hosting_provider": "Unknown", "organization": "Tor Project", "network_type": "anonymization", "is_vpn_proxy_tor": True, "reputation": "Poor"},
        "198.51.100.14": {"country": "United States", "region": "Virginia", "city": "Ashburn", "isp": "Amazon AWS Cloud", "asn": "AS16509", "hosting_provider": "AWS", "organization": "Amazon.com Inc.", "network_type": "cloud", "is_vpn_proxy_tor": False, "reputation": "Neutral"},
        "203.0.113.88": {"country": "India", "region": "Maharashtra", "city": "Mumbai", "isp": "Reliance Jio Infocomm", "asn": "AS55836", "hosting_provider": "Unknown", "organization": "Reliance Jio", "network_type": "residential", "is_vpn_proxy_tor": False, "reputation": "Good"},
        "45.33.32.156": {"country": "United States", "region": "Texas", "city": "Dallas", "isp": "Linode LLC", "asn": "AS63949", "hosting_provider": "Linode", "organization": "Linode", "network_type": "cloud", "is_vpn_proxy_tor": False, "reputation": "Neutral"},
        "103.21.244.0": {"country": "Singapore", "region": "Singapore", "city": "Singapore", "isp": "Cloudflare Inc", "asn": "AS13335", "hosting_provider": "Cloudflare", "organization": "Cloudflare", "network_type": "cdn", "is_vpn_proxy_tor": False, "reputation": "Good"},
    }

    def get_ip_intel(self, ip_address: str) -> Dict[str, Any]:
        intel = {
            "ip": ip_address,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "asn": "Unknown",
            "isp": "Unknown",
            "hosting_provider": "Unknown",
            "organization": "Unknown",
            "network_type": "Unknown",
            "is_vpn_proxy_tor": False,
            "reputation": "Unknown",
            "is_mock": True,
            "caveat": "Estimated infrastructure geolocation. Probable source infrastructure observed. VPNs, proxies, cloud hosting, and compromised systems may obscure the actual origin. Do not interpret as exact attacker location."
        }
        
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                intel["network_type"] = "private"
                intel["reputation"] = "Neutral"
                return intel
        except ValueError:
            return intel

        if ip_address in self.MOCK_GEO_DATABASE:
            mock_data = self.MOCK_GEO_DATABASE[ip_address]
            for k, v in mock_data.items():
                intel[k] = v
            return intel
        
        # Deterministic fallback for other IPs
        hash_val = sum(ord(c) for c in ip_address)
        sample_cities = [
            {"country": "Germany", "region": "Berlin", "city": "Berlin", "isp": "Deutsche Telekom", "asn": "AS3320", "network_type": "residential", "reputation": "Good"},
            {"country": "Netherlands", "region": "North Holland", "city": "Amsterdam", "isp": "Serverius Holding", "asn": "AS50673", "network_type": "hosting", "reputation": "Neutral"},
            {"country": "Russia", "region": "Moscow", "city": "Moscow", "isp": "Rostelecom", "asn": "AS12389", "network_type": "residential", "reputation": "Unknown"},
            {"country": "United States", "region": "California", "city": "San Jose", "isp": "Cogent Communications", "asn": "AS174", "network_type": "business", "reputation": "Good"},
            {"country": "United Kingdom", "region": "England", "city": "London", "isp": "British Telecom", "asn": "AS2856", "network_type": "residential", "reputation": "Good"}
        ]
        
        chosen = sample_cities[hash_val % len(sample_cities)]
        intel.update(chosen)
        intel["is_vpn_proxy_tor"] = (hash_val % 4 == 0)
        if intel["is_vpn_proxy_tor"]:
            intel["network_type"] = "anonymization"
            intel["reputation"] = "Poor"
        
        return intel

class IPIntelEngine:
    def __init__(self, provider: IPIntelProvider = None):
        self.provider = provider or MockIPIntelProvider()

    def analyze_ips(self, ip_list: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Analyzes a list of IP addresses and returns a dictionary 
        mapping the IP address to its intelligence data.
        """
        results = {}
        # Remove duplicates
        unique_ips = list(set(ip_list))
        for ip in unique_ips:
            results[ip] = self.provider.get_ip_intel(ip)
        return results
