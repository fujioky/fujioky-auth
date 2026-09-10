from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column


def create_models(base, user_table="users"):
    """Use the application's metadata and engine; no extra database/service."""
    class LoginSession(base):
        __tablename__ = "auth_sessions"
        id: Mapped[str] = mapped_column(String(64), primary_key=True)  # cookie SHA256
        user_id: Mapped[int] = mapped_column(ForeignKey(user_table + ".id", ondelete="CASCADE"), index=True)
        issuer: Mapped[str] = mapped_column(String(500))
        sub: Mapped[str] = mapped_column(String(200), index=True)
        sid: Mapped[str] = mapped_column(String(200), default="", index=True)
        tokens: Mapped[str] = mapped_column(Text, default="")  # authenticated encryption
        token_expires: Mapped[int] = mapped_column(Integer)
        expires: Mapped[int] = mapped_column(Integer, index=True)
        created: Mapped[int] = mapped_column(Integer)
        last_seen: Mapped[int] = mapped_column(Integer)
        agent: Mapped[str] = mapped_column(String(300), default="")
        revoked: Mapped[bool] = mapped_column(Boolean, default=False)
        refresh_until: Mapped[int] = mapped_column(Integer, default=0)
        refresh_owner: Mapped[str] = mapped_column(String(100), default="")

    class LogoutEvent(base):
        __tablename__ = "auth_logout_events"
        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        expires: Mapped[int] = mapped_column(Integer, index=True)

    return LoginSession, LogoutEvent
