import urllib.parse
from typing import Dict, Any, List
from abc import ABC, abstractmethod

class DomainIntelProvider(ABC):
    @abstractmethod
    def get_domain_intel(self, domain: str) -> Dict[str, Any]:
        pass

class DefaultDomainIntelProvider(DomainIntelProvider):
    """
    Fallback provider when no external DNS/WHOIS API is available.
    """
    def get_domain_intel(self, domain: str) -> Dict[str, Any]:
        return {
            "domain": domain,
            "domain_age": "Unavailable",
            "registrar": "Unavailable",
            "dns_records": "Unavailable",
            "mx_records": "Unavailable",
            "nameservers": "Unavailable"
        }

class URLIntelEngine:
    HIGH_VALUE_BRANDS = [
        "google", "microsoft", "paypal", "apple", "amazon", 
        "netflix", "facebook", "linkedin", "bankofamerica", "chase"
    ]
    
    # Common character substitutions (homoglyphs)
    SUBSTITUTIONS = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 
        '7': 't', '8': 'b', 'rn': 'm', 'cl': 'd', 'vv': 'w'
    }

    def __init__(self, domain_provider: DomainIntelProvider = None):
        self.domain_provider = domain_provider or DefaultDomainIntelProvider()

    def analyze_urls(self, raw_urls: List[str]) -> List[Dict[str, Any]]:
        results = []
        for raw_url in raw_urls:
            intel = self._analyze_single(raw_url)
            results.append(intel)
        return results

    def _analyze_single(self, raw_url: str) -> Dict[str, Any]:
        # Basic extraction
        url_details = self._parse_url(raw_url)
        domain = url_details["hostname"]

        if domain:
            domain_intel = self.domain_provider.get_domain_intel(domain)
            lookalike_intel = self._detect_lookalike(domain)
            is_suspicious = lookalike_intel.get("is_typosquatted", False)
        else:
            domain_intel = {}
            lookalike_intel = {"is_typosquatted": False, "matched_brand": None, "distance": 0, "reason": None}
            is_suspicious = False

        return {
            "url": raw_url,
            "domain": domain if domain else "",
            "is_suspicious": is_suspicious,
            "is_typosquatted": lookalike_intel.get("is_typosquatted", False),
            "reputation_score": 0.0 if is_suspicious else 100.0,
            "url_details": url_details,
            "domain_intel": domain_intel,
            "lookalike_intel": lookalike_intel
        }

    def _parse_url(self, raw_url: str) -> Dict[str, Any]:
        try:
            parsed = urllib.parse.urlparse(raw_url)
            if not parsed.scheme and not raw_url.startswith('//'):
                parsed = urllib.parse.urlparse('//' + raw_url)
            
            query_params = urllib.parse.parse_qs(parsed.query)
            
            # Very basic redirect indicator check
            redirect_indicators = False
            if "url=" in parsed.query.lower() or "redirect=" in parsed.query.lower() or "next=" in parsed.query.lower():
                redirect_indicators = True

            return {
                "protocol": parsed.scheme,
                "hostname": parsed.hostname or "",
                "path": parsed.path,
                "query_parameters": query_params,
                "redirect_indicators": redirect_indicators
            }
        except Exception:
            return {
                "protocol": "",
                "hostname": "",
                "path": "",
                "query_parameters": {},
                "redirect_indicators": False
            }

    def _detect_lookalike(self, hostname: str) -> Dict[str, Any]:
        # Remove TLD for basic brand comparison
        parts = hostname.split('.')
        base_domain = parts[-2] if len(parts) >= 2 else parts[0]
        
        # Check against high-value brands
        for brand in self.HIGH_VALUE_BRANDS:
            if base_domain == brand:
                return {"is_typosquatted": False, "matched_brand": None, "distance": 0, "reason": None}
            
            dist = self._levenshtein(base_domain, brand)
            if 0 < dist <= 2 and len(brand) > 4:  # Typosquat threshold
                return {
                    "is_typosquatted": True,
                    "matched_brand": brand,
                    "distance": dist,
                    "reason": f"Levenshtein distance of {dist} to {brand}"
                }
                
            # Check for character substitution
            normalized = base_domain
            for k, v in self.SUBSTITUTIONS.items():
                normalized = normalized.replace(k, v)
                
            if normalized == brand:
                return {
                    "is_typosquatted": True,
                    "matched_brand": brand,
                    "distance": 0,
                    "reason": "Character substitution/homoglyph detected"
                }

        # Subdomain suspicious patterns (e.g. login.paypal.com.evil.com)
        if len(parts) > 2:
            subdomains = ".".join(parts[:-2]).lower()
            for brand in self.HIGH_VALUE_BRANDS:
                if brand in subdomains:
                    return {
                        "is_typosquatted": True,
                        "matched_brand": brand,
                        "distance": 0,
                        "reason": f"Brand '{brand}' found in subdomain (phishing indicator)"
                    }

        return {"is_typosquatted": False, "matched_brand": None, "distance": 0, "reason": None}

    def _levenshtein(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
