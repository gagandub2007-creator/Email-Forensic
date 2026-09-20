import logging
from typing import Dict, List, Any, Optional, Set
from sqlalchemy.orm import Session
from app.models.entities import EmailRecord, EmailHop, ExtractedURL, AttachmentRecord, Case

logger = logging.getLogger(__name__)

class HistoricalCorrelationEngine:
    """
    Correlates a newly or previously analyzed email against historical forensic database records.
    Enforces cautious, non-definitive threat intelligence language:
    - "Related historical activity"
    - "Potential campaign relationship"
    - "Observed shared infrastructure"
    """

    @staticmethod
    def _extract_domain(email_or_url: Optional[str]) -> Optional[str]:
        if not email_or_url:
            return None
        val = email_or_url.strip().lower()
        if "@" in val:
            return val.split("@")[-1]
        if "://" in val:
            val = val.split("://")[1].split("/")[0].split(":")[0]
        return val.lower() if val else None

    @classmethod
    def correlate_email(cls, email_id: str, db: Session) -> Dict[str, Any]:
        target_email = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
        if not target_email:
            return cls._empty_correlation_response("Target email record not found")

        # 1. Collect target email artifacts
        target_sender = (target_email.sender_address or "").strip().lower()
        target_sender_domain = cls._extract_domain(target_sender)
        target_reply_to_domain = cls._extract_domain(target_email.reply_to)
        
        target_domains: Set[str] = set()
        if target_email.domains:
            target_domains.update([d.lower() for d in target_email.domains if d])
        if target_sender_domain:
            target_domains.add(target_sender_domain)
        if target_reply_to_domain:
            target_domains.add(target_reply_to_domain)

        target_urls: Set[str] = set()
        for u in target_email.urls or []:
            if u.url:
                target_urls.add(u.url.strip().lower())
                if u.domain:
                    target_domains.add(u.domain.strip().lower())

        target_ips: Set[str] = set()
        if target_email.originating_ip and target_email.originating_ip != "0.0.0.0":
            target_ips.add(target_email.originating_ip.strip())
        if target_email.ipv4_addresses:
            target_ips.update([ip for ip in target_email.ipv4_addresses if ip])
        if target_email.ipv6_addresses:
            target_ips.update([ip for ip in target_email.ipv6_addresses if ip])

        target_asns: Set[str] = set()
        target_isps: Set[str] = set()
        target_countries: Set[str] = set()

        for hop in target_email.hops or []:
            if hop.ip_address and hop.ip_address != "0.0.0.0":
                target_ips.add(hop.ip_address.strip())
            if hop.asn and hop.asn != "Unknown ASN":
                target_asns.add(hop.asn.strip())
            if hop.isp and hop.isp != "Unknown Provider":
                target_isps.add(hop.isp.strip())
            if hop.country and hop.country != "Unknown":
                target_countries.add(hop.country.strip())

        target_attachment_hashes: Dict[str, str] = {}
        for att in target_email.attachments or []:
            if att.sha256_hash:
                target_attachment_hashes[att.sha256_hash.strip().lower()] = att.filename

        target_msg_id_domain = cls._extract_domain(target_email.message_id)

        # 2. Query other emails in DB
        other_emails = db.query(EmailRecord).filter(EmailRecord.id != email_id).all()

        related_investigations: List[Dict[str, Any]] = []
        shared_domains_all: Set[str] = set()
        shared_urls_all: Set[str] = set()
        shared_ips_all: Set[str] = set()
        shared_asns_all: Set[str] = set()
        shared_isps_all: Set[str] = set()
        shared_attachment_hashes_all: Set[str] = set()
        matched_email_ids: Set[str] = set()

        for other in other_emails:
            matched_artifacts: List[str] = []

            # Check Sender match
            other_sender = (other.sender_address or "").strip().lower()
            if target_sender and other_sender == target_sender:
                matched_artifacts.append(f"Sender Address ({target_sender})")

            # Check Sender Domain match
            other_sender_domain = cls._extract_domain(other_sender)
            if target_sender_domain and other_sender_domain == target_sender_domain:
                matched_artifacts.append(f"Sender Domain ({target_sender_domain})")
                shared_domains_all.add(target_sender_domain)

            # Check Reply-To domain
            other_reply_to_dom = cls._extract_domain(other.reply_to)
            if target_reply_to_domain and other_reply_to_dom == target_reply_to_domain:
                matched_artifacts.append(f"Reply-To Domain ({target_reply_to_domain})")
                shared_domains_all.add(target_reply_to_domain)

            # Check URLs & Domains
            other_urls = {u.url.strip().lower() for u in other.urls or [] if u.url}
            other_domains = {u.domain.strip().lower() for u in other.urls or [] if u.domain}
            if other.domains:
                other_domains.update([d.lower() for d in other.domains if d])

            common_urls = target_urls.intersection(other_urls)
            if common_urls:
                matched_artifacts.append(f"{len(common_urls)} Shared URL(s)")
                shared_urls_all.update(common_urls)

            common_domains = target_domains.intersection(other_domains)
            if common_domains:
                matched_artifacts.append(f"{len(common_domains)} Shared Domain(s)")
                shared_domains_all.update(common_domains)

            # Check IPs & Infrastructure
            other_ips: Set[str] = set()
            if other.originating_ip and other.originating_ip != "0.0.0.0":
                other_ips.add(other.originating_ip.strip())
            if other.ipv4_addresses:
                other_ips.update([ip for ip in other.ipv4_addresses if ip])

            other_asns: Set[str] = set()
            other_isps: Set[str] = set()
            for hop in other.hops or []:
                if hop.ip_address:
                    other_ips.add(hop.ip_address.strip())
                if hop.asn and hop.asn != "Unknown ASN":
                    other_asns.add(hop.asn.strip())
                if hop.isp and hop.isp != "Unknown Provider":
                    other_isps.add(hop.isp.strip())

            common_ips = target_ips.intersection(other_ips)
            if common_ips:
                matched_artifacts.append(f"{len(common_ips)} Shared IP(s)")
                shared_ips_all.update(common_ips)

            common_asns = target_asns.intersection(other_asns)
            if common_asns:
                shared_asns_all.update(common_asns)
            
            common_isps = target_isps.intersection(other_isps)
            if common_isps:
                shared_isps_all.update(common_isps)

            # Check Attachments
            other_att_hashes = {att.sha256_hash.strip().lower() for att in other.attachments or [] if att.sha256_hash}
            common_atts = set(target_attachment_hashes.keys()).intersection(other_att_hashes)
            if common_atts:
                matched_artifacts.append(f"{len(common_atts)} Identical Attachment Hash(es)")
                shared_attachment_hashes_all.update(common_atts)

            # Check Message-ID domain
            other_msg_id_dom = cls._extract_domain(other.message_id)
            if target_msg_id_domain and other_msg_id_dom == target_msg_id_domain:
                matched_artifacts.append(f"Message-ID Domain Pattern ({target_msg_id_domain})")

            # If any matched artifacts exist, add to related investigations
            if matched_artifacts:
                matched_email_ids.add(other.id)
                case_obj = other.case
                case_number = case_obj.case_number if case_obj else f"CASE-{other.case_id[:8] if other.case_id else 'UNK'}"
                case_title = case_obj.title if case_obj else "Forensic Investigation"
                subj_str = (other.subject or "No Subject")[:100]

                related_investigations.append({
                    "email_id": other.id,
                    "case_id": other.case_id,
                    "case_number": case_number,
                    "case_title": case_title,
                    "subject_summary": subj_str,
                    "sender_address": other.sender_address,
                    "threat_level": other.threat_level,
                    "analyzed_at": other.analyzed_at.isoformat() if other.analyzed_at else None,
                    "matched_artifacts": matched_artifacts
                })

        # 3. Determine Potential Campaign Relationship (with cautious phrasing)
        has_campaign_indicators = len(related_investigations) > 0 or len(shared_domains_all) > 0 or len(shared_urls_all) > 0
        campaign_confidence = min(0.35 + (len(related_investigations) * 0.15) + (len(shared_urls_all) * 0.1), 0.92) if has_campaign_indicators else 0.0

        observed_indicators: List[str] = []
        if shared_domains_all:
            observed_indicators.append(f"{len(shared_domains_all)} shared domain(s) observed: {', '.join(list(shared_domains_all)[:3])}")
        if shared_urls_all:
            observed_indicators.append(f"{len(shared_urls_all)} shared suspicious URL(s) detected across historical logs")
        if shared_ips_all:
            observed_indicators.append(f"{len(shared_ips_all)} shared originating/relay IP(s) identified")
        if shared_attachment_hashes_all:
            observed_indicators.append(f"{len(shared_attachment_hashes_all)} identical attachment payload hash(es) matched")
        if shared_asns_all:
            observed_indicators.append(f"Infrastructure overlap detected across ASN(s): {', '.join(list(shared_asns_all)[:2])}")

        # Strict Cautious Language
        campaign_desc = (
            f"Potential campaign relationship observed across {len(related_investigations)} historical investigation(s) "
            f"based on shared infrastructure, domain overlaps, and matching attack artifacts. "
            f"Note: This reflects statistical and topological correlation; further investigation is required for definitive attribution."
            if has_campaign_indicators else
            "No historical threat correlations or shared campaign artifacts were observed for this email."
        )

        return {
            "target_email_id": email_id,
            "correlation_status": "COMPLETED",
            "previous_occurrences_count": len(related_investigations),
            "related_investigations": related_investigations,
            "shared_infrastructure": {
                "shared_ips": list(shared_ips_all),
                "shared_asns": list(shared_asns_all),
                "shared_isps": list(shared_isps_all),
                "shared_countries": list(target_countries)
            },
            "shared_domains": list(shared_domains_all),
            "shared_urls": list(shared_urls_all),
            "shared_ips": list(shared_ips_all),
            "shared_attachments": [
                {"hash": h, "filename": target_attachment_hashes.get(h, "attachment.bin")}
                for h in shared_attachment_hashes_all
            ],
            "potential_campaign": {
                "has_potential_campaign": has_campaign_indicators,
                "confidence_score": round(campaign_confidence, 2),
                "campaign_name": "Potential BEC & Multi-Vector Impersonation Activity" if has_campaign_indicators else "Uncorrelated Activity",
                "description": campaign_desc,
                "observed_indicators": observed_indicators,
                "cautious_language_disclaimer": "Related historical activity reflects statistical and topological correlation. Absolute attribution requires out-of-band verification."
            }
        }

    @classmethod
    def _empty_correlation_response(cls, message: str) -> Dict[str, Any]:
        return {
            "target_email_id": "",
            "correlation_status": "NO_DATA",
            "previous_occurrences_count": 0,
            "related_investigations": [],
            "shared_infrastructure": {
                "shared_ips": [],
                "shared_asns": [],
                "shared_isps": [],
                "shared_countries": []
            },
            "shared_domains": [],
            "shared_urls": [],
            "shared_ips": [],
            "shared_attachments": [],
            "potential_campaign": {
                "has_potential_campaign": False,
                "confidence_score": 0.0,
                "campaign_name": "Uncorrelated Activity",
                "description": message,
                "observed_indicators": [],
                "cautious_language_disclaimer": "Related historical activity reflects statistical correlation."
            }
        }
