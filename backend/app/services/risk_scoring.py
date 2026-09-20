import re
from typing import Dict, Any

class RiskScoringEngine:
    """
    Deterministic risk scoring engine.
    Calculates a 0-100 score based on modular weights.
    """
    
    # Modular weights that can be tuned later
    WEIGHTS = {
        "AUTH_FAILURE": 15,
        "SUSPICIOUS_SENDER_DOMAIN": 25,
        "REPLY_TO_MISMATCH": 20,
        "SUSPICIOUS_URL": 17,
        "MALICIOUS_ATTACHMENT": 35,
        "IMPERSONATION_SIGNALS": 25,
        "PAYMENT_FRAUD_INDICATORS": 10,
        "PHISHING_LANGUAGE": 15
    }

    SUSPICIOUS_TLDS = [".xyz", ".top", ".biz", ".work", ".click", ".gq", ".tk", ".cf", ".ml"]

    @classmethod
    def calculate_risk(
        cls,
        parsed_email: Dict[str, Any],
        hops: list,
        ai_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        
        score = 0
        factors = []
        
        # 1. Authentication Failures
        spf = parsed_email.get("spf_status", "UNKNOWN")
        dkim = parsed_email.get("dkim_status", "UNKNOWN")
        dmarc = parsed_email.get("dmarc_status", "UNKNOWN")
        
        if dmarc == "FAIL":
            score += cls.WEIGHTS["AUTH_FAILURE"]
            factors.append(f"+{cls.WEIGHTS['AUTH_FAILURE']} DMARC failure")
        elif spf == "FAIL" or dkim == "FAIL":
            score += cls.WEIGHTS["AUTH_FAILURE"]
            factors.append(f"+{cls.WEIGHTS['AUTH_FAILURE']} SPF/DKIM failure")

        # 2. Sender / Domain Anomalies
        sender_address = parsed_email.get("sender_address", "").lower()
        reply_to = parsed_email.get("reply_to", "").lower()
        
        if any(sender_address.endswith(tld) for tld in cls.SUSPICIOUS_TLDS):
            score += cls.WEIGHTS["SUSPICIOUS_SENDER_DOMAIN"]
            factors.append(f"+{cls.WEIGHTS['SUSPICIOUS_SENDER_DOMAIN']} suspicious sender domain")
            
        if reply_to and sender_address and reply_to != sender_address:
            score += cls.WEIGHTS["REPLY_TO_MISMATCH"]
            factors.append(f"+{cls.WEIGHTS['REPLY_TO_MISMATCH']} Reply-To mismatch")

        # 3. Suspicious URLs
        urls = parsed_email.get("urls", [])
        has_suspicious_url = False
        for url in urls:
            domain = cls._extract_domain(url)
            if any(domain.endswith(tld) for tld in cls.SUSPICIOUS_TLDS) or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                has_suspicious_url = True
                break
        
        if has_suspicious_url:
            score += cls.WEIGHTS["SUSPICIOUS_URL"]
            factors.append(f"+{cls.WEIGHTS['SUSPICIOUS_URL']} suspicious URL")

        # 4. Attachment Risk
        attachments = parsed_email.get("attachments", [])
        has_bad_attachment = False
        for att in attachments:
            fname = att.get("filename", "").lower()
            if any(fname.endswith(ext) for ext in [".exe", ".scr", ".bat", ".vbs", ".js", ".iso", ".zip", ".docm", ".xlsm"]):
                has_bad_attachment = True
                break
                
        if has_bad_attachment:
            score += cls.WEIGHTS["MALICIOUS_ATTACHMENT"]
            factors.append(f"+{cls.WEIGHTS['MALICIOUS_ATTACHMENT']} malicious attachment")

        # 5. Impersonation & BEC/Payment Language (Using AI Signals)
        # Instead of recalculating, we can rely on the signals outputted by the AI model.
        ai_signals = str(ai_analysis.get("signals", [])).lower()
        ai_class = ai_analysis.get("classification", "")
        
        if "impersonation" in ai_signals or ai_class == "Impersonation":
            score += cls.WEIGHTS["IMPERSONATION_SIGNALS"]
            factors.append(f"+{cls.WEIGHTS['IMPERSONATION_SIGNALS']} impersonation pattern")
            
        if "financial" in ai_signals or ai_class == "Business Email Compromise":
            score += cls.WEIGHTS["PAYMENT_FRAUD_INDICATORS"]
            factors.append(f"+{cls.WEIGHTS['PAYMENT_FRAUD_INDICATORS']} payment fraud indicators")
            
        if "credential" in ai_signals or ai_class == "Phishing":
            score += cls.WEIGHTS["PHISHING_LANGUAGE"]
            factors.append(f"+{cls.WEIGHTS['PHISHING_LANGUAGE']} phishing indicators")

        # Cap score at 100
        final_score = min(score, 100)

        # Severity Mapping
        if final_score <= 30:
            severity = "Low"
        elif final_score <= 60:
            severity = "Medium"
        elif final_score <= 80:
            severity = "High"
        else:
            severity = "Critical"
            
        return {
            "risk_score": final_score,
            "severity": severity,
            "contributing_factors": factors
        }

    @staticmethod
    def _extract_domain(url: str) -> str:
        match = re.search(r'https?://([^/]+)', url)
        if match:
            return match.group(1).lower()
        if '/' in url:
            return url.split('/')[0].lower()
        return url.lower()
