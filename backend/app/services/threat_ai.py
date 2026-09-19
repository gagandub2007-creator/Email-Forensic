import re
from typing import Dict, Any, List

class AIThreatEngine:
    # High Risk Urgency & Fraud Triggers
    BEC_KEYWORDS = [
        "wire transfer", "direct deposit", "gift card", "ceo office", "urgent request",
        "update banking details", "payroll change", "confidential invoice", "swift transfer",
        "w-2 form", "tax document", "immediate action required", "w-9 form"
    ]
    
    PHISHING_KEYWORDS = [
        "verify account", "suspend account", "password reset", "unauthorized login",
        "confirm identity", "security alert", "click here", "update password",
        "invoice attached", "overdue payment", "limited time offer", "claim reward"
    ]

    SUSPICIOUS_TLDS = [".xyz", ".top", ".biz", ".work", ".click", ".gq", ".tk", ".cf", ".ml"]

    @classmethod
    def analyze_email_threat(
        cls,
        parsed_email: Dict[str, Any],
        hops: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Executes multi-layer AI threat analysis:
        1. NLP Intent Analysis (BEC, Phishing, Scam probability)
        2. Header Anomaly Matrix
        3. URL Reputation & Typosquatting inspection
        4. Calculates overall 0-100 threat score & level
        """
        subject = parsed_email.get("subject", "")
        body = (parsed_email.get("body_plain", "") + " " + parsed_email.get("body_html", "")).lower()
        sender_address = parsed_email.get("sender_address", "").lower()
        sender_name = parsed_email.get("sender_name", "").lower()
        spf = parsed_email.get("spf_status", "UNKNOWN")
        dkim = parsed_email.get("dkim_status", "UNKNOWN")
        dmarc = parsed_email.get("dmarc_status", "UNKNOWN")
        urls = parsed_email.get("urls", [])
        attachments = parsed_email.get("attachments", [])

        # 1. NLP Keyword & Keyphrase Detection
        detected_bec = [kw for kw in cls.BEC_KEYWORDS if kw in body or kw in subject.lower()]
        detected_phishing = [kw for kw in cls.PHISHING_KEYWORDS if kw in body or kw in subject.lower()]

        # 2. Probability Scores
        bec_prob = min(len(detected_bec) * 0.35 + (0.25 if "ceo" in sender_name else 0.0), 0.99)
        phishing_prob = min(len(detected_phishing) * 0.30, 0.99)
        scam_prob = min((len(detected_bec) + len(detected_phishing)) * 0.20, 0.99)

        # 3. Header Anomaly Matrix
        header_anomaly_score = 0.0
        if spf == "FAIL":
            header_anomaly_score += 25.0
        if dkim == "FAIL":
            header_anomaly_score += 25.0
        if dmarc == "FAIL":
            header_anomaly_score += 25.0

        # Display Name Spoofing Check (e.g. Name contains 'CEO' or 'Executive' but domain is free email like gmail.com or scam domain)
        if any(term in sender_name for term in ["ceo", "executive", "director", "admin", "helpdesk", "support"]):
            if any(free_domain in sender_address for free_domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]):
                header_anomaly_score += 30.0
                detected_bec.append("display_name_free_email_spoof")

        # Check for TOR or VPN Hop Routing
        has_tor_hop = any(hop.get("is_vpn_proxy_tor", False) for hop in hops)
        if has_tor_hop:
            header_anomaly_score += 20.0

        # 4. URL Reputation & Typosquatting Analysis
        analyzed_urls = []
        url_threat_penalty = 0.0
        for url in urls:
            is_suspicious = False
            is_typosquatted = False
            domain = cls._extract_domain(url)

            if any(domain.endswith(tld) for tld in cls.SUSPICIOUS_TLDS):
                is_suspicious = True
                url_threat_penalty += 15.0

            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): # Raw IP URL
                is_suspicious = True
                url_threat_penalty += 20.0

            if "-" in domain or "login" in domain or "verify" in domain or "secure" in domain:
                is_typosquatted = True
                url_threat_penalty += 15.0

            rep_score = 100.0 - (40.0 if is_suspicious else 0.0) - (40.0 if is_typosquatted else 0.0)
            rep_score = max(rep_score, 0.0)

            analyzed_urls.append({
                "url": url,
                "domain": domain,
                "is_suspicious": is_suspicious,
                "is_typosquatted": is_typosquatted,
                "reputation_score": rep_score
            })

        # 5. Attachment Malware Check
        attachment_penalty = 0.0
        for att in attachments:
            fname = att.get("filename", "").lower()
            if any(fname.endswith(ext) for ext in [".exe", ".scr", ".bat", ".vbs", ".js", ".iso", ".zip", ".docm", ".xlsm"]):
                attachment_penalty += 35.0
                att["is_malicious"] = True
                att["threat_description"] = "Executable or Macro-enabled Attachment"

        # 6. Overall Threat Score Calculation (Weighted Normalized 0-100)
        total_threat_score = (
            (bec_prob * 35.0) +
            (phishing_prob * 25.0) +
            (header_anomaly_score * 0.25) +
            url_threat_penalty +
            attachment_penalty
        )
        total_threat_score = round(min(max(total_threat_score, 0.0), 100.0), 1)

        # Assign Threat Level
        if total_threat_score >= 80.0:
            threat_level = "CRITICAL"
        elif total_threat_score >= 50.0:
            threat_level = "HIGH_RISK"
        elif total_threat_score >= 25.0:
            threat_level = "SUSPICIOUS"
        else:
            threat_level = "CLEAN"

        return {
            "overall_threat_score": total_threat_score,
            "threat_level": threat_level,
            "phishing_probability": round(phishing_prob, 2),
            "bec_probability": round(bec_prob, 2),
            "scam_probability": round(scam_prob, 2),
            "header_anomaly_score": round(min(header_anomaly_score, 100.0), 1),
            "detected_keywords": detected_bec + detected_phishing,
            "key_phrases": [subject] if subject else [],
            "analyzed_urls": analyzed_urls
        }

    @staticmethod
    def _extract_domain(url: str) -> str:
        match = re.search(r'https?://([^/]+)', url)
        if match:
            return match.group(1).lower()
        return url.split('/')[0].lower()
