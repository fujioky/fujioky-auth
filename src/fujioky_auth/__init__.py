"""Reusable Logto/OIDC authentication for FastAPI applications."""
from .config import AuthConfig
from .manager import AuthManager, upsert_standard_user
from .web import safe_next

__all__ = ["AuthConfig", "AuthManager", "upsert_standard_user", "safe_next"]
