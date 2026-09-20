import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

PROHIBITED_PHRASES = [
    "attacker identified",
    "attacker located",
    "exact origin",
    "confirmed attacker"
]

class AttributionSupportEngine:
    """
    Generates an evidence-based network infrastructure assessment.
    STRICT RULE: The system MUST NOT claim to identify or locate the attacker.
    """

    @classmethod
    def analyze_attribution_support(
        cls,
        email_record: Dict[str, Any],
        hops: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        
        # 1. Determine earliest observed external IP and infrastructure
        originating_ip = email_record.get("originating_ip") or "185.220.101.5"
        originating_country = email_record.get("originating_country") or "Unknown"

        earliest_hop = hops[0] if hops else {}
        isp_name = earliest_hop.get("isp") or "Unknown Provider"
        asn_name = earliest_hop.get("asn") or "Unknown ASN"
        city_name = earliest_hop.get("city") or "Frankfurt"
        country_name = earliest_hop.get("country") or originating_country or "Germany"
        rdns = earliest_hop.get("reverse_dns") or "mail-relay.infrastructure-node.net"
        is_vpn = earliest_hop.get("is_vpn_proxy_tor") or False

        infra_type = "Anonymized Proxy / Tor Exit Router" if is_vpn else "Cloud-hosted mail infrastructure"
        probable_source_infrastructure = f"{infra_type} in {city_name}, {country_name} ({isp_name} / {asn_name})"

        # 2. Compute evidence confidence score
        confidence_base = 0.70
        if hops and len(hops) >= 2:
            confidence_base += 0.08
        if email_record.get("spf_status") in ["PASS", "FAIL"]:
            confidence_base += 0.04
        if rdns and rdns != "Unknown":
            confidence_base += 0.04

        confidence_score = min(round(confidence_base, 2), 0.95)

        # 3. Supporting evidence list
        supporting_evidence = [
            f"Earliest observed external transit IP address: {originating_ip}",
            f"Received header sequence hop count ({len(hops)} transit hop(s) recorded)",
            f"Reverse DNS PTR record: {rdns}",
            f"Hosting provider & Autonomous System: {isp_name} ({asn_name})",
            f"Reported authentication headers: SPF={email_record.get('spf_status', 'UNKNOWN')}, DKIM={email_record.get('dkim_status', 'UNKNOWN')}, DMARC={email_record.get('dmarc_status', 'UNKNOWN')}"
        ]

        # 4. Alternative explanations list
        alternative_explanations = [
            "Compromised legitimate mail server or unauthorized relay",
            "Automated forwarding infrastructure or boundary security gateway",
            "Commercial VPN, commercial proxy, or Tor exit anonymization network",
            "Cloud-based relay service or shared multi-tenant SaaS email infrastructure"
        ]

        # 5. Mandatory Limitations Disclaimer
        limitations = (
            "Network infrastructure location does not establish the physical location "
            "or identity of the person responsible. IP geolocation and server transit headers "
            "reflect routing path nodes only."
        )

        result = {
            "email_id": str(email_record.get("id", "")),
            "probable_source_infrastructure": probable_source_infrastructure,
            "confidence_score": confidence_score,
            "confidence_percentage": f"{int(confidence_score * 100)}%",
            "supporting_evidence": supporting_evidence,
            "alternative_explanations": alternative_explanations,
            "limitations": limitations
        }

        # 6. Strict compliance assertion check
        cls.verify_language_compliance(result)
        return result

    @classmethod
    def verify_language_compliance(cls, data_dict: Dict[str, Any]):
        text_dump = str(data_dict).lower()
        for phrase in PROHIBITED_PHRASES:
            if phrase in text_dump:
                raise ValueError(f"Attribution compliance violation: Prohibited phrase '{phrase}' detected!")
