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
        for header, value in msg.items():
            headers[header] = str(value)

        raw_headers_str = "\n".join([f"{k}: {v}" for k, v in msg.items()])

        sender = msg.get("From", "")
        sender_address, sender_name = cls._extract_email_address_and_name(sender)
        recipient = msg.get("To", "")
        recipient_address, _ = cls._extract_email_address_and_name(recipient)
        subject = msg.get("Subject", "(No Subject)")
        date_str = msg.get("Date", "")
        email_date = cls._parse_date(date_str)
        message_id = msg.get("Message-ID", "")

        # Extract Authentication Headers
        spf_status, dkim_status, dmarc_status = cls._extract_auth_results(msg)

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

        return {
            "sha256_hash": sha256_hash,
            "message_id": message_id,
            "subject": subject,
            "sender_address": sender_address,
            "sender_name": sender_name,
            "recipient_address": recipient_address,
            "email_date": email_date,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "raw_headers": raw_headers_str,
            "body_plain": body_plain,
            "body_html": body_html,
            "received_headers": [str(r) for r in received_headers],
            "attachments": attachments,
            "urls": urls
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
    def _extract_auth_results(msg) -> tuple:
        spf_status = "UNKNOWN"
        dkim_status = "UNKNOWN"
        dmarc_status = "UNKNOWN"

        auth_res = msg.get("Authentication-Results", "") + " " + msg.get("Received-SPF", "")
        auth_res_lower = auth_res.lower()

        if "spf=pass" in auth_res_lower or "pass" in msg.get("Received-SPF", "").lower():
            spf_status = "PASS"
        elif "spf=fail" in auth_res_lower or "spf=softfail" in auth_res_lower or "fail" in msg.get("Received-SPF", "").lower():
            spf_status = "FAIL"

        if "dkim=pass" in auth_res_lower:
            dkim_status = "PASS"
        elif "dkim=fail" in auth_res_lower:
            dkim_status = "FAIL"

        if "dmarc=pass" in auth_res_lower:
            dmarc_status = "PASS"
        elif "dmarc=fail" in auth_res_lower:
            dmarc_status = "FAIL"

        return spf_status, dkim_status, dmarc_status

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
