import re
import hashlib
from datetime import datetime
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List

class EmailParserEngine:
    @staticmethod
    def calculate_sha256(raw_bytes: bytes) -> str:
        return hashlib.sha256(raw_bytes).hexdigest()

    @classmethod
    def parse_eml_bytes(cls, raw_bytes: bytes) -> Dict[str, Any]:
        """Parses RFC 822 .eml byte stream and returns structured metadata."""
        sha256_hash = cls.calculate_sha256(raw_bytes)
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        headers = {}
        x_headers = {}
        for header, value in msg.items():
            headers[header] = str(value)
            if header.lower().startswith('x-'):
                x_headers[header] = str(value)

        raw_headers_str = "\n".join([f"{k}: {v}" for k, v in msg.items()])

        sender = msg.get("From", "")
        sender_address, sender_name = cls._extract_email_address_and_name(sender)
        recipient = msg.get("To", "")
        recipient_address, _ = cls._extract_email_address_and_name(recipient)
        cc = msg.get("Cc", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        subject = msg.get("Subject", "(No Subject)")
        date_str = msg.get("Date", "")
        email_date = cls._parse_date(date_str)
        message_id = msg.get("Message-ID", "")

        # Extract Authentication Headers
        auth_data = cls._extract_auth_results(msg)
        spf_status = auth_data["spf_status"]
        dkim_status = auth_data["dkim_status"]
        dmarc_status = auth_data["dmarc_status"]

        # Extract Body Content
        body_plain = ""
        body_html = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                if "attachment" not in content_disposition:
                    if content_type == "text/plain" and not body_plain:
                        body_plain = part.get_content()
                    elif content_type == "text/html" and not body_html:
                        body_html = part.get_content()
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                body_plain = msg.get_content()
            elif content_type == "text/html":
                body_html = msg.get_content()

        if not body_plain and body_html:
            # Simple fallback strip tags for body_plain
            body_plain = re.sub(r'<[^>]+>', ' ', body_html)

        # Extract Received Hops
        received_headers = msg.get_all("Received") or []

        # Extract Attachments
        attachments = cls._extract_attachments(msg)

        # Extract URLs from HTML and Plain Text
        urls = cls._extract_urls(body_plain + " " + body_html)
        domains = cls._extract_domains(urls)

        ipv4_addresses = cls._extract_ipv4(body_plain + " " + body_html + " " + raw_headers_str)
        ipv6_addresses = cls._extract_ipv6(body_plain + " " + body_html + " " + raw_headers_str)

        earliest_external_source = None
        if received_headers:
            # Simple heuristic: last received header usually represents the earliest external source (first hop)
            earliest_external_source = str(received_headers[-1])

        return {
            "sha256_hash": sha256_hash,
            "message_id": message_id,
            "subject": subject,
            "sender_address": sender_address,
            "sender_name": sender_name,
            "recipient_address": recipient_address,
            "cc": cc,
            "reply_to": reply_to,
            "return_path": return_path,
            "email_date": email_date,
            "spf_status": spf_status,
            "spf_details": auth_data["spf_details"],
            "dkim_status": dkim_status,
            "dkim_details": auth_data["dkim_details"],
            "dmarc_status": dmarc_status,
            "dmarc_details": auth_data["dmarc_details"],
            "auth_caveat": auth_data["auth_caveat"],
            "raw_headers": raw_headers_str,
            "x_headers": x_headers,
            "body_plain": body_plain,
            "body_html": body_html,
            "received_headers": [str(r) for r in received_headers],
            "attachments": attachments,
            "urls": urls,
            "domains": domains,
            "ipv4_addresses": ipv4_addresses,
            "ipv6_addresses": ipv6_addresses,
            "earliest_external_source": earliest_external_source
        }

    @staticmethod
    def _extract_email_address_and_name(from_header: str) -> tuple:
        if not from_header:
            return "", ""
        match = re.search(r'(?:"?([^"]*)"?\s)?<([^>]+)>', from_header)
        if match:
            name = match.group(1).strip() if match.group(1) else ""
            address = match.group(2).strip()
            return address.lower(), name
        elif "@" in from_header:
            return from_header.strip().lower(), ""
        return from_header.strip(), ""

    @staticmethod
    def _parse_date(date_str: str) -> datetime:
        if not date_str:
            return datetime.utcnow()
        try:
            parsed_tuple = email.utils.parsedate_to_datetime(date_str)
            return parsed_tuple.replace(tzinfo=None)
        except Exception:
            return datetime.utcnow()

    @staticmethod
    def _extract_auth_results(msg) -> Dict[str, Any]:
        spf_details = {"status": "UNKNOWN", "domain": None, "explanation": None}
        dkim_details = {"status": "UNKNOWN", "domain": None, "selector": None, "explanation": None}
        dmarc_details = {"status": "UNKNOWN", "policy": None, "aligned_domain": None, "explanation": None}

        auth_res = msg.get("Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")
        
        auth_res_lower = auth_res.lower()
        recv_spf_lower = received_spf.lower()

        # Parse SPF
        if "spf=pass" in auth_res_lower or "pass" in recv_spf_lower:
            spf_details["status"] = "PASS"
        elif "spf=fail" in auth_res_lower or "fail" in recv_spf_lower:
            spf_details["status"] = "FAIL"
        elif "spf=softfail" in auth_res_lower or "softfail" in recv_spf_lower:
            spf_details["status"] = "SOFTFAIL"
        elif "spf=neutral" in auth_res_lower or "neutral" in recv_spf_lower:
            spf_details["status"] = "NEUTRAL"
        elif "spf=none" in auth_res_lower or "none" in recv_spf_lower:
            spf_details["status"] = "NONE"

        spf_domain_match = re.search(r'smtp\.mailfrom=([^\s;]+)', auth_res_lower)
        if spf_domain_match:
            spf_details["domain"] = spf_domain_match.group(1)
            
        spf_details["explanation"] = f"Reported SPF status is {spf_details['status']}."

        # Parse DKIM
        if "dkim=pass" in auth_res_lower:
            dkim_details["status"] = "PASS"
        elif "dkim=fail" in auth_res_lower:
            dkim_details["status"] = "FAIL"
        elif "dkim=none" in auth_res_lower:
            dkim_details["status"] = "NONE"

        dkim_domain_match = re.search(r'header\.d=([^\s;]+)', auth_res_lower)
        dkim_selector_match = re.search(r'header\.s=([^\s;]+)', auth_res_lower)
        
        if dkim_domain_match:
            dkim_details["domain"] = dkim_domain_match.group(1)
        if dkim_selector_match:
            dkim_details["selector"] = dkim_selector_match.group(1)
            
        dkim_details["explanation"] = f"Reported DKIM status is {dkim_details['status']}."

        # Parse DMARC
        if "dmarc=pass" in auth_res_lower:
            dmarc_details["status"] = "PASS"
        elif "dmarc=fail" in auth_res_lower:
            dmarc_details["status"] = "FAIL"
        elif "dmarc=none" in auth_res_lower:
            dmarc_details["status"] = "NONE"

        dmarc_domain_match = re.search(r'header\.from=([^\s;]+)', auth_res_lower)
        dmarc_policy_match = re.search(r'policy\.published=([^\s;]+)', auth_res_lower) or re.search(r'policy=([^\s;]+)', auth_res_lower)
        
        if dmarc_domain_match:
            dmarc_details["aligned_domain"] = dmarc_domain_match.group(1)
        if dmarc_policy_match:
            dmarc_details["policy"] = dmarc_policy_match.group(1)
            
        dmarc_details["explanation"] = f"Reported DMARC status is {dmarc_details['status']}."

        auth_caveat = "Note: These are reported authentication results parsed from headers, not independently verified cryptographic results."

        return {
            "spf_status": spf_details["status"],
            "spf_details": spf_details,
            "dkim_status": dkim_details["status"],
            "dkim_details": dkim_details,
            "dmarc_status": dmarc_details["status"],
            "dmarc_details": dmarc_details,
            "auth_caveat": auth_caveat
        }

    @classmethod
    def _extract_attachments(cls, msg) -> List[Dict[str, Any]]:
        attachments = []
        if not msg.is_multipart():
            return attachments

        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition"))
            filename = part.get_filename()

            if "attachment" in content_disposition or filename:
                filename = filename or "unnamed_attachment"
                content = part.get_payload(decode=True) or b""
                mime_type = part.get_content_type()
                file_hash = hashlib.sha256(content).hexdigest()

                attachments.append({
                    "filename": filename,
                    "mime_type": mime_type,
                    "file_size_bytes": len(content),
                    "sha256_hash": file_hash,
                    "content": content
                })
        return attachments

    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        if not text:
            return []
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        matches = re.findall(url_pattern, text)
        cleaned_urls = []
        for url in matches:
            url = url.rstrip('.,;()[]{}')
            if url not in cleaned_urls:
                cleaned_urls.append(url)
        return cleaned_urls

    @staticmethod
    def _extract_domains(urls: List[str]) -> List[str]:
        domains = set()
        for url in urls:
            match = re.search(r'https?://([^/:]+)', url)
            if match:
                domains.add(match.group(1).lower())
            elif url.startswith('www.'):
                domains.add(url.split('/')[0].lower())
        return list(domains)

    @staticmethod
    def _extract_ipv4(text: str) -> List[str]:
        if not text:
            return []
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, text)
        return list(set(matches))

    @staticmethod
    def _extract_ipv6(text: str) -> List[str]:
        if not text:
            return []
        # Basic IPv6 regex
        ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:)*::(?:[A-Fa-f0-9]{1,4}:)*[A-Fa-f0-9]{1,4}\b'
        matches = re.findall(ipv6_pattern, text)
        return list(set(matches))
