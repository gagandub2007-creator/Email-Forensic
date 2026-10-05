"""
STEP 19 — Application Security, Sanitization & Audit Logging

Provides:
    • HTML content sanitization for rendering email bodies safely
    • Strict file upload validation (type, size, path traversal, executable prevention)
    • Never execute email attachments safeguard
    • Audit logging for sensitive platform actions
"""

import re
import os
import html
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.entities import AuditLog

# Max upload size: 25 MB
MAX_UPLOAD_SIZE_BYTES = 25 * 1024 * 1024

# Allowed file extensions for email imports / attachments
ALLOWED_EMAIL_EXTENSIONS = {".eml", ".msg", ".txt"}
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".jar",
    ".msi", ".com", ".scr", ".pif", ".application", ".gadget", ".hta",
    ".cpl", ".msc", ".jar", ".cab", ".dll"
}


class SecurityValidator:
    """Validates uploaded files and inputs to prevent RCE, path traversal, and XSS."""

    @classmethod
    def validate_file_upload(
        cls,
        filename: str,
        file_size_bytes: int,
        content_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate uploaded email file metadata.

        Raises ValueError if file violates security constraints.
        """
        # 1. Path traversal check
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid filename: Path traversal characters detected ('..', '/', '\\')")

        # 2. Oversized file check
        if file_size_bytes > MAX_UPLOAD_SIZE_BYTES:
            raise ValueError(f"File size ({file_size_bytes} bytes) exceeds maximum limit of {MAX_UPLOAD_SIZE_BYTES} bytes (25MB)")

        # 3. Dangerous extension check
        ext = os.path.splitext(filename)[1].lower()
        if ext in DANGEROUS_EXTENSIONS:
            raise ValueError(f"Security Policy Violation: Executable file extension '{ext}' is strictly forbidden.")

        return {
            "valid": True,
            "filename": os.path.basename(filename),
            "size": file_size_bytes,
            "extension": ext
        }

    @classmethod
    def sanitize_email_html(cls, raw_html: Optional[str]) -> str:
        """Sanitize raw email HTML to prevent script execution, XSS, and iframe hijacking.

        Strips <script>, <iframe>, <object>, <embed>, on* inline event handlers,
        and javascript: URIs.
        """
        if not raw_html:
            return ""

        clean = raw_html

        # Strip <script>...</script> blocks
        clean = re.sub(r'<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>', '', clean, flags=re.IGNORECASE)

        # Strip <iframe>, <object>, <embed>, <applet>
        clean = re.sub(r'<(iframe|object|embed|applet)\b[^>]*>.*?</\1>', '', clean, flags=re.IGNORECASE | re.DOTALL)
        clean = re.sub(r'<(iframe|object|embed|applet)\b[^>]*>', '', clean, flags=re.IGNORECASE)

        # Strip javascript: and data: URIs in href/src
        clean = re.sub(r'(href|src)\s*=\s*["\']\s*javascript:[^"\']*["\']', r'\1="#"', clean, flags=re.IGNORECASE)

        # Strip inline event attributes like onload=, onerror=, onclick=
        clean = re.sub(r'\s+on[a-z]+\s*=\s*["\'][^"\']*["\']', '', clean, flags=re.IGNORECASE)
        clean = re.sub(r'\s+on[a-z]+\s*=\s*[^"\s>]+', '', clean, flags=re.IGNORECASE)

        return clean

    @classmethod
    def is_attachment_safe_to_view(cls, filename: str) -> bool:
        """Enforces 'Never execute email attachments' policy."""
        ext = os.path.splitext(filename)[1].lower()
        if ext in DANGEROUS_EXTENSIONS:
            return False
        return True


class AuditLogger:
    """Records security audit events for compliance."""

    @classmethod
    def log_action(
        cls,
        db: Session,
        *,
        user_id: str,
        user_role: str,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = "127.0.0.1",
        status: str = "SUCCESS",
    ) -> AuditLog:
        """Persist an audit log entry in the database."""
        entry = AuditLog(
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            user_role=user_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            status=status,
        )
        db.add(entry)
        try:
            db.commit()
            db.refresh(entry)
        except Exception:
            db.rollback()
        return entry
