import re
from typing import Dict, Any, List
from abc import ABC, abstractmethod

class ThreatDetectionProvider(ABC):
    """
    Abstract base class for threat detection models/providers.
    This allows swapping between baseline heuristics, scikit-learn, XGBoost, or LLMs.
    """
    @abstractmethod
    def analyze(self, parsed_email: Dict[str, Any], hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes the email and returns a dictionary with:
        - classification (str)
        - confidence (float)
        - signals (List[str])
        - model_info (str)
        - overall_threat_score (float)
        - threat_level (str)
        """
        pass

class BaselineHeuristicDetector(ThreatDetectionProvider):
    """
    Transparent baseline detection model based on heuristics.
    """
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

    def analyze(self, parsed_email: Dict[str, Any], hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        subject = parsed_email.get("subject", "")
        body = (parsed_email.get("body_plain", "") + " " + parsed_email.get("body_html", "")).lower()
        sender_address = parsed_email.get("sender_address", "").lower()
        sender_name = parsed_email.get("sender_name", "").lower()
        spf = parsed_email.get("spf_status", "UNKNOWN")
        dkim = parsed_email.get("dkim_status", "UNKNOWN")
        dmarc = parsed_email.get("dmarc_status", "UNKNOWN")
        urls = parsed_email.get("urls", [])
        attachments = parsed_email.get("attachments", [])

        signals = []
        scores = {
            "Business Email Compromise": 0.0,
            "Phishing": 0.0,
            "Malicious Link": 0.0,
            "Suspicious Attachment": 0.0,
            "Impersonation": 0.0
        }

        # 1. Content Analysis
        detected_bec = [kw for kw in self.BEC_KEYWORDS if kw in body or kw in subject.lower()]
        if detected_bec:
            scores["Business Email Compromise"] += len(detected_bec) * 0.3
            signals.append(f"Financial/urgent language detected: {', '.join(detected_bec)}")

        detected_phishing = [kw for kw in self.PHISHING_KEYWORDS if kw in body or kw in subject.lower()]
        if detected_phishing:
            scores["Phishing"] += len(detected_phishing) * 0.3
            signals.append(f"Credential/account alert language detected: {', '.join(detected_phishing)}")

        # 2. Sender / Impersonation
        if any(term in sender_name for term in ["ceo", "executive", "director", "admin", "helpdesk", "support"]):
            if any(free_domain in sender_address for free_domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]):
                scores["Impersonation"] += 0.8
                scores["Business Email Compromise"] += 0.4
                signals.append("Display name impersonates authority using a free email provider")

        # 3. Authentication
        if spf == "FAIL" or dkim == "FAIL" or dmarc == "FAIL":
            scores["Phishing"] += 0.4
            signals.append(f"Authentication failure (SPF: {spf}, DKIM: {dkim}, DMARC: {dmarc})")

        # 4. URLs
        for url in urls:
            domain = self._extract_domain(url)
            if any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                scores["Malicious Link"] += 0.5
                signals.append(f"Suspicious URL TLD detected: {domain}")
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                scores["Malicious Link"] += 0.6
                signals.append(f"URL uses raw IP address instead of domain: {url}")
            if "-" in domain or "login" in domain or "verify" in domain or "secure" in domain:
                scores["Phishing"] += 0.2
                signals.append(f"Typosquatting or phishing keywords in domain: {domain}")

        # 5. Attachments
        for att in attachments:
            fname = att.get("filename", "").lower()
            if any(fname.endswith(ext) for ext in [".exe", ".scr", ".bat", ".vbs", ".js", ".iso", ".zip", ".docm", ".xlsm"]):
                scores["Suspicious Attachment"] += 0.9
                signals.append(f"Executable or dangerous attachment detected: {fname}")

        # Determine highest score
        max_class = "Legitimate"
        max_score = 0.0
        
        for classification, score in scores.items():
            if score > max_score:
                max_score = score
                max_class = classification

        # Normalize confidence to 0.0 - 0.99
        confidence = min(max_score, 0.99)

        if confidence < 0.3:
            max_class = "Legitimate"
            confidence = 0.9 # High confidence it's legitimate if no signals
            if not signals:
                signals.append("No suspicious indicators detected")

        # Calculate legacy 0-100 overall score for standard mapping
        overall_threat_score = round(confidence * 100, 1) if max_class != "Legitimate" else 0.0

        if overall_threat_score >= 80.0:
            threat_level = "CRITICAL"
        elif overall_threat_score >= 50.0:
            threat_level = "HIGH_RISK"
        elif overall_threat_score >= 25.0:
            threat_level = "SUSPICIOUS"
        else:
            threat_level = "CLEAN"

        return {
            "classification": max_class,
            "confidence": round(confidence, 2),
            "signals": list(set(signals)),  # Deduplicate
            "model_info": "Baseline Heuristic Detector v1.0",
            "overall_threat_score": overall_threat_score,
            "threat_level": threat_level
        }

    @staticmethod
    def _extract_domain(url: str) -> str:
        match = re.search(r'https?://([^/]+)', url)
        if match:
            return match.group(1).lower()
        return url.split('/')[0].lower()


class AIThreatEngine:
    _provider = BaselineHeuristicDetector()

    @classmethod
    def set_provider(cls, provider: ThreatDetectionProvider):
        cls._provider = provider

    @classmethod
    def analyze_email_threat(
        cls,
        parsed_email: Dict[str, Any],
        hops: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Delegates analysis to the configured AI provider.
        """
        return cls._provider.analyze(parsed_email, hops)
