import os
import time
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from sqlalchemy import JSON, DateTime, Integer, LargeBinary, String, create_engine, delete, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://cryptix:change-me@localhost:5432/cryptix")
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class Base(DeclarativeBase):
    pass


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    credential_id: Mapped[str] = mapped_column(String(1024), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(255), index=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(nullable=False, default=0)
    transports: Mapped[list[str] | None] = mapped_column(JSON_TYPE, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lost_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WebAuthnChallenge(Base):
    __tablename__ = "webauthn_challenges"

    user_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RememberedBrowser(Base):
    __tablename__ = "remembered_browsers"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(255), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EmailCode(Base):
    __tablename__ = "email_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(255), index=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def initialize_database() -> None:
    Base.metadata.create_all(engine)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def cleanup_expired(session: Session) -> None:
    now = utc_now()
    session.execute(delete(WebAuthnChallenge).where(WebAuthnChallenge.expires_at < now))
    session.execute(delete(RememberedBrowser).where(RememberedBrowser.expires_at < now))
    session.execute(delete(EmailCode).where(EmailCode.expires_at < now))


def save_challenge(session: Session, user_id: str, purpose: str, session_id: str, challenge: bytes, ttl_seconds: int) -> None:
    record = session.get(WebAuthnChallenge, (user_id, purpose, session_id))
    if record is None:
        record = WebAuthnChallenge(user_id=user_id, purpose=purpose, session_id=session_id, challenge=challenge, expires_at=utc_now())
        session.add(record)
    record.challenge = challenge
    record.expires_at = datetime.fromtimestamp(time.time() + ttl_seconds, timezone.utc)


def consume_challenge(session: Session, user_id: str, purpose: str, session_id: str) -> bytes | None:
    record = session.get(WebAuthnChallenge, (user_id, purpose, session_id), with_for_update=True)
    if record is None or record.expires_at < utc_now():
        if record is not None:
            session.delete(record)
        return None
    value = record.challenge
    session.delete(record)
    return value


def credential_rows(session: Session, user_id: str, include_lost: bool = False) -> list[PasskeyCredential]:
    statement = select(PasskeyCredential).where(PasskeyCredential.user_id == user_id)
    if not include_lost:
        statement = statement.where(PasskeyCredential.lost_at.is_(None))
    return list(session.scalars(statement).all())


def serialize_credential(row: PasskeyCredential) -> dict[str, Any]:
    return {"credentialId": row.credential_id, "createdAt": row.created_at, "lostAt": row.lost_at}