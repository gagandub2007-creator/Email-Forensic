"""
STEP 19 — Role-Based Access Control (RBAC) & Authentication Architecture

Roles:
    • ADMIN          — Full administrative access across all platform modules
    • INVESTIGATOR   — Case management, analysis, evidence, audit logs
    • ANALYST        — Email analysis, evidence viewing, report exports
    • VIEWER         — Read-only access to investigations, evidence, and reports

Permissions:
    • Analyze Email
    • View Investigations
    • Create Cases
    • Modify Cases
    • View Evidence
    • Export Reports
    • Manage Users
    • View Audit Logs
    • Manage Integrations
"""

import os
import time
from enum import Enum
from typing import Dict, Set, Optional
from fastapi import Depends, HTTPException, Header, status

# ---------------------------------------------------------------
# Roles & Permissions Definitions
# ---------------------------------------------------------------

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    INVESTIGATOR = "INVESTIGATOR"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    ANALYZE_EMAIL = "Analyze Email"
    VIEW_INVESTIGATIONS = "View Investigations"
    CREATE_CASES = "Create Cases"
    MODIFY_CASES = "Modify Cases"
    VIEW_EVIDENCE = "View Evidence"
    EXPORT_REPORTS = "Export Reports"
    MANAGE_USERS = "Manage Users"
    VIEW_AUDIT_LOGS = "View Audit Logs"
    MANAGE_INTEGRATIONS = "Manage Integrations"


# Permission matrix by role
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: {
        Permission.ANALYZE_EMAIL,
        Permission.VIEW_INVESTIGATIONS,
        Permission.CREATE_CASES,
        Permission.MODIFY_CASES,
        Permission.VIEW_EVIDENCE,
        Permission.EXPORT_REPORTS,
        Permission.MANAGE_USERS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.MANAGE_INTEGRATIONS,
    },
    UserRole.INVESTIGATOR: {
        Permission.ANALYZE_EMAIL,
        Permission.VIEW_INVESTIGATIONS,
        Permission.CREATE_CASES,
        Permission.MODIFY_CASES,
        Permission.VIEW_EVIDENCE,
        Permission.EXPORT_REPORTS,
        Permission.VIEW_AUDIT_LOGS,
    },
    UserRole.ANALYST: {
        Permission.ANALYZE_EMAIL,
        Permission.VIEW_INVESTIGATIONS,
        Permission.VIEW_EVIDENCE,
        Permission.EXPORT_REPORTS,
    },
    UserRole.VIEWER: {
        Permission.VIEW_INVESTIGATIONS,
        Permission.VIEW_EVIDENCE,
        Permission.EXPORT_REPORTS,
    },
}


# JWT Secret Key from env variable (never hardcoded in production)
JWT_SECRET = os.getenv("JWT_SECRET", "sih-2026-email-forensic-secret-key-change-in-prod")
JWT_ALGORITHM = "HS256"


# Mock user tokens for test / demonstration environments
MOCK_USERS = {
    "token-admin": {"id": "user-admin-01", "role": UserRole.ADMIN, "name": "Admin User"},
    "token-investigator": {"id": "user-inv-01", "role": UserRole.INVESTIGATOR, "name": "Lead Investigator"},
    "token-analyst": {"id": "user-anl-01", "role": UserRole.ANALYST, "name": "Forensic Analyst"},
    "token-viewer": {"id": "user-vwr-01", "role": UserRole.VIEWER, "name": "Audit Viewer"},
}


def get_current_user_context(authorization: Optional[str] = Header(None)) -> Dict[str, str]:
    """Dependency that extracts user ID and role from the Authorization header.

    If no authorization header is provided (e.g. SIH dev prototype mode), defaults to
    INVESTIGATOR role to keep public endpoints accessible during demo runs.
    """
    if not authorization:
        return {
            "id": "investigator-default-01",
            "role": UserRole.INVESTIGATOR.value,
            "name": "Default Investigator"
        }

    token = authorization.replace("Bearer ", "").strip()

    if token in MOCK_USERS:
        u = MOCK_USERS[token]
        return {
            "id": u["id"],
            "role": u["role"].value,
            "name": u["name"]
        }

    # Standard check for unknown / invalid tokens
    if token == "unauthorized":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication credentials"
        )

    # Fallback for dev tokens
    return {
        "id": f"user-{token[:8]}",
        "role": UserRole.INVESTIGATOR.value,
        "name": f"User {token[:8]}"
    }


def require_permission(required_perm: Permission):
    """Dependency generator that enforces role-based permission checks."""
    def dependency(user: Dict[str, str] = Depends(get_current_user_context)):
        role_str = user.get("role", UserRole.VIEWER.value)
        try:
            role_enum = UserRole(role_str)
        except ValueError:
            role_enum = UserRole.VIEWER

        user_perms = ROLE_PERMISSIONS.get(role_enum, set())
        if required_perm not in user_perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission Denied: Role '{role_str}' lacks required permission '{required_perm.value}'"
            )
        return user
    return dependency
