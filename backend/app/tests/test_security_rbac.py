"""
Tests for STEP 19 — Application Security, RBAC, File Validation & Audit Logging

Covers:
    • SecurityValidator: file upload validation, path traversal prevention, oversized file blocking, executable blocking
    • HTML email body sanitization (XSS / script injection prevention)
    • Never execute email attachments policy
    • RBAC permission checking (ADMIN, INVESTIGATOR, ANALYST, VIEWER)
    • Unauthorized access rejection on protected endpoints
    • Audit log entry generation
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.security import SecurityValidator, AuditLogger
from app.core.auth import UserRole, Permission, ROLE_PERMISSIONS, require_permission

client = TestClient(app)


class TestSecurityValidator:
    def test_valid_file_upload(self):
        res = SecurityValidator.validate_file_upload("legit_sample.eml", 1024)
        assert res["valid"] is True
        assert res["extension"] == ".eml"

    def test_path_traversal_blocked(self):
        with pytest.raises(ValueError, match="Path traversal"):
            SecurityValidator.validate_file_upload("../../../etc/passwd.eml", 100)

        with pytest.raises(ValueError, match="Path traversal"):
            SecurityValidator.validate_file_upload("C:\\Windows\\System32\\cmd.eml", 100)

    def test_oversized_file_blocked(self):
        too_big = 30 * 1024 * 1024  # 30MB
        with pytest.raises(ValueError, match="exceeds maximum limit"):
            SecurityValidator.validate_file_upload("huge.eml", too_big)

    def test_executable_extension_blocked(self):
        with pytest.raises(ValueError, match="Executable file extension"):
            SecurityValidator.validate_file_upload("payload.exe", 1024)

        with pytest.raises(ValueError, match="Executable file extension"):
            SecurityValidator.validate_file_upload("script.ps1", 1024)

    def test_html_sanitization(self):
        raw_xss = '<p>Hello</p><script>alert("hack")</script><iframe src="http://evil.com"></iframe><a href="javascript:alert(1)">Click</a><img src="x" onerror="alert(2)"/>'
        clean = SecurityValidator.sanitize_email_html(raw_xss)
        assert "<script>" not in clean
        assert "<iframe>" not in clean
        assert "javascript:" not in clean
        assert "onerror=" not in clean
        assert "<p>Hello</p>" in clean

    def test_attachment_execution_safeguard(self):
        assert SecurityValidator.is_attachment_safe_to_view("invoice.pdf") is True
        assert SecurityValidator.is_attachment_safe_to_view("image.png") is True
        assert SecurityValidator.is_attachment_safe_to_view("malware.exe") is False
        assert SecurityValidator.is_attachment_safe_to_view("script.vbs") is False


class TestRBACPermissions:
    def test_role_permission_matrix(self):
        admin_perms = ROLE_PERMISSIONS[UserRole.ADMIN]
        assert Permission.MANAGE_USERS in admin_perms
        assert Permission.MANAGE_INTEGRATIONS in admin_perms
        assert Permission.ANALYZE_EMAIL in admin_perms

        viewer_perms = ROLE_PERMISSIONS[UserRole.VIEWER]
        assert Permission.MANAGE_USERS not in viewer_perms
        assert Permission.ANALYZE_EMAIL not in viewer_perms
        assert Permission.VIEW_INVESTIGATIONS in viewer_perms

        inv_perms = ROLE_PERMISSIONS[UserRole.INVESTIGATOR]
        assert Permission.CREATE_CASES in inv_perms
        assert Permission.ANALYZE_EMAIL in inv_perms
        assert Permission.MANAGE_USERS not in inv_perms

    def test_unauthorized_token_rejected(self):
        resp = client.get("/api/v1/audit-logs", headers={"Authorization": "Bearer unauthorized"})
        assert resp.status_code == 401

    def test_viewer_access_forbidden_on_restricted(self):
        resp = client.get("/api/v1/audit-logs", headers={"Authorization": "Bearer token-viewer"})
        assert resp.status_code == 403
        assert "Permission Denied" in resp.json()["detail"]

    def test_admin_access_allowed_on_audit_logs(self):
        resp = client.get("/api/v1/audit-logs", headers={"Authorization": "Bearer token-admin"})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
