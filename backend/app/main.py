import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from .db import (
    EmailCode,
    PasskeyCredential,
    RememberedBrowser,
    SessionLocal,
    WebAuthnChallenge,
    cleanup_expired,
    consume_challenge,
    credential_rows,
    initialize_database,
    save_challenge,
    serialize_credential,
    as_utc,
    utc_now,
)
from .email_service import send_verification_email
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

load_dotenv()

RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "Cryptix")
RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
EXPECTED_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:5173")
SECRET_KEY = os.getenv("WEBAUTHN_SECRET_KEY", "development-only-change-me")
CHALLENGE_TTL_SECONDS = 120
REMEMBERED_BROWSER_TTL_SECONDS = 30 * 24 * 60 * 60
allowed_frontend_origins = {
    os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"),
    "http://localhost:5173",
    "http://127.0.0.1:5173",
}


serializer = URLSafeTimedSerializer(SECRET_KEY, salt="cryptix-remembered-browser")

app = FastAPI(title="Cryptix Passkey Service", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(allowed_frontend_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-User-Id", "X-User-Email", "X-Username", "X-Session-Id"],
)


def current_user(user_id: str | None, email: str | None, username: str | None = None) -> tuple[str, str]:
    """Temporary adapter until M1's email-based session middleware is shared."""
    return user_id or os.getenv("DEMO_USER_ID", "demo-user"), email or username or os.getenv("DEMO_USERNAME", "demo@example.com")


def json_error(code: str, message: str, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": code, "message": message})


@app.on_event("startup")
def startup() -> None:
    initialize_database()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/mfa/email/send", status_code=status.HTTP_202_ACCEPTED)
def send_email_code(
    payload: dict[str, Any],
    x_user_id: str | None = Header(default=None),
    x_user_email: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
) -> dict[str, str]:
    email = str(payload.get("email") or x_user_email or "").strip().lower()
    purpose = str(payload.get("purpose") or "login")
    if "@" not in email or purpose not in {"login", "registration", "recovery"}:
        raise json_error("email_code_request_invalid", "Enter a valid email address and try again.", 400)
    user_id, _ = current_user(x_user_id, email)
    session_id = x_session_id or "development-session"
    code = f"{secrets.randbelow(1_000_000):06d}"
    code_hash = hashlib.sha256(f"{SECRET_KEY}:{user_id}:{purpose}:{session_id}:{email}:{code}".encode()).hexdigest()
    try:
        send_verification_email(email, code)
    except RuntimeError as error:
        raise json_error("email_delivery_not_configured", str(error), 503) from error
    with SessionLocal.begin() as session:
        cleanup_expired(session)
        session.query(EmailCode).filter_by(user_id=user_id, purpose=purpose, session_id=session_id, used_at=None).delete()
        session.add(EmailCode(
            user_id=user_id,
            email=email,
            purpose=purpose,
            session_id=session_id,
            code_hash=code_hash,
            expires_at=datetime.fromtimestamp(time.time() + 600, timezone.utc),
        ))
    return {"status": "sent", "message": "A verification code was sent to your email address."}


@app.post("/mfa/email/verify")
def verify_email_code(
    payload: dict[str, Any],
    x_user_id: str | None = Header(default=None),
    x_user_email: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
) -> dict[str, str]:
    email = str(payload.get("email") or x_user_email or "").strip().lower()
    code = str(payload.get("code") or "").strip()
    purpose = str(payload.get("purpose") or "login")
    if not email or not code.isdigit() or len(code) != 6:
        raise json_error("email_code_invalid", "Enter the six digit verification code from your email.", 400)
    user_id, _ = current_user(x_user_id, email)
    session_id = x_session_id or "development-session"
    with SessionLocal.begin() as session:
        cleanup_expired(session)
        record = session.scalar(select(EmailCode).where(
            EmailCode.user_id == user_id,
            EmailCode.email == email,
            EmailCode.purpose == purpose,
            EmailCode.session_id == session_id,
            EmailCode.used_at.is_(None),
        ).order_by(EmailCode.id.desc()).limit(1).with_for_update())
        if record is None or record.expires_at < utc_now() or record.attempts >= 5:
            raise json_error("email_code_invalid", "No active code matches this email and sign-in session. Use the newest code from your latest email, or request a new code.", 400)
        expected = hashlib.sha256(f"{SECRET_KEY}:{user_id}:{purpose}:{session_id}:{email}:{code}".encode()).hexdigest()
        if not secrets.compare_digest(record.code_hash, expected):
            record.attempts += 1
            raise json_error("email_code_invalid", "That code is not valid. Check the email and try again.", 400)
        record.used_at = utc_now()
    return {"next": "done" if purpose == "login" else "factor_setup"}


@app.post("/webauthn/register/options")
def registration_options(
    x_user_id: str | None = Header(default=None),
    x_user_email: str | None = Header(default=None),
    x_username: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
) -> Any:
    user_id, email = current_user(x_user_id, x_user_email, x_username)
    session_id = x_session_id or "development-session"
    with SessionLocal.begin() as session:
        cleanup_expired(session)
        existing = credential_rows(session, user_id)
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id.encode("utf-8"),
            user_name=email,
            user_display_name=email,
            exclude_credentials=[base64url_to_bytes(item.credential_id) for item in existing],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            timeout=CHALLENGE_TTL_SECONDS * 1000,
        )
        save_challenge(session, user_id, "registration", session_id, options.challenge, CHALLENGE_TTL_SECONDS)
    return json.loads(options_to_json(options))


@app.post("/webauthn/register/verify")
def registration_verify(
    credential: dict[str, Any],
    x_user_id: str | None = Header(default=None),
    x_user_email: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
) -> dict[str, str]:
    user_id, _ = current_user(x_user_id, x_user_email)
    with SessionLocal.begin() as session:
        challenge = consume_challenge(session, user_id, "registration", x_session_id or "development-session")
    if challenge is None:
        raise json_error("challenge_expired", "Your passkey challenge has expired. Start this step again.", 400)
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge.value,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
            require_user_verification=False,
        )
    except Exception as error:
        raise json_error("registration_failed", "The passkey could not be registered. Try again.", 400) from error
    if not verification.verified or verification.registration_info is None:
        raise json_error("registration_failed", "The passkey could not be registered. Try again.", 400)
    info = verification.registration_info
    credential_id = bytes_to_base64url(info.credential_id)
    with SessionLocal.begin() as session:
        existing = session.get(PasskeyCredential, credential_id)
        if existing is not None and existing.lost_at is None:
            raise json_error("credential_exists", "This passkey is already registered.", 409)
        if existing is not None:
            session.delete(existing)
        session.add(PasskeyCredential(
            credential_id=credential_id,
            user_id=user_id,
            public_key=info.credential_public_key,
            sign_count=info.sign_count,
            transports=credential.get("response", {}).get("transports", []),
            created_at=utc_now(),
        ))
    return {"credentialId": credential_id}


@app.post("/webauthn/login/options")
def authentication_options(
    x_user_id: str | None = Header(default=None),
    x_user_email: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
) -> Any:
    user_id, _ = current_user(x_user_id, x_user_email)
    with SessionLocal.begin() as session:
        cleanup_expired(session)
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=[base64url_to_bytes(item.credential_id) for item in credential_rows(session, user_id)],
            user_verification=UserVerificationRequirement.PREFERRED,
            timeout=CHALLENGE_TTL_SECONDS * 1000,
        )
        save_challenge(session, user_id, "authentication", x_session_id or "development-session", options.challenge, CHALLENGE_TTL_SECONDS)
    return json.loads(options_to_json(options))


@app.post("/webauthn/login/verify")
def authentication_verify(
    assertion: dict[str, Any],
    x_user_id: str | None = Header(default=None),
    x_user_email: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
) -> dict[str, str]:
    user_id, _ = current_user(x_user_id, x_user_email)
    with SessionLocal.begin() as session:
        challenge = consume_challenge(session, user_id, "authentication", x_session_id or "development-session")
    if challenge is None:
        raise json_error("challenge_expired", "Your passkey challenge has expired. Start this step again.", 400)
    credential_id = assertion.get("id")
    with SessionLocal() as session:
        stored = session.scalar(select(PasskeyCredential).where(
            PasskeyCredential.credential_id == credential_id,
            PasskeyCredential.user_id == user_id,
            PasskeyCredential.lost_at.is_(None),
        ))
    if stored is None:
        raise json_error("credential_not_found", "This passkey is not available for your account.", 404)
    try:
        verification = verify_authentication_response(
            credential=assertion,
            expected_challenge=challenge.value,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=False,
        )
    except Exception as error:
        raise json_error("authentication_failed", "Passkey verification failed. Try again.", 401) from error
    if not verification.verified:
        raise json_error("authentication_failed", "Passkey verification failed. Try again.", 401)
    with SessionLocal.begin() as session:
        stored = session.get(PasskeyCredential, credential_id)
        if stored is not None:
            stored.sign_count = verification.new_sign_count
    return {"next": "done"}


@app.get("/webauthn/credentials")
def list_credentials(x_user_id: str | None = Header(default=None)) -> list[dict[str, Any]]:
    user_id, _ = current_user(x_user_id, None)
    with SessionLocal() as session:
        return [serialize_credential(item) for item in credential_rows(session, user_id, include_lost=True)]


@app.post("/webauthn/credentials/{credential_id}/lost")
def report_lost(credential_id: str, x_user_id: str | None = Header(default=None)) -> dict[str, str]:
    user_id, _ = current_user(x_user_id, None)
    with SessionLocal.begin() as session:
        stored = session.scalar(select(PasskeyCredential).where(
            PasskeyCredential.credential_id == credential_id,
            PasskeyCredential.user_id == user_id,
            PasskeyCredential.lost_at.is_(None),
        ))
        if stored is None:
            raise json_error("credential_not_found", "This passkey is not available for your account.", 404)
        stored.lost_at = utc_now()
    return {"status": "lost"}


@app.delete("/webauthn/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_credential(credential_id: str, x_user_id: str | None = Header(default=None)) -> None:
    user_id, _ = current_user(x_user_id, None)
    with SessionLocal.begin() as session:
        stored = session.scalar(select(PasskeyCredential).where(
            PasskeyCredential.credential_id == credential_id,
            PasskeyCredential.user_id == user_id,
        ))
        if stored is None:
            raise json_error("credential_not_found", "This passkey is not available for your account.", 404)
        session.delete(stored)


@app.post("/device/remember")
def remember_browser(x_user_id: str | None = Header(default=None)) -> dict[str, str]:
    user_id, _ = current_user(x_user_id, None)
    token = serializer.dumps({"user_id": user_id, "nonce": secrets.token_urlsafe(24)})
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with SessionLocal.begin() as session:
        cleanup_expired(session)
        session.add(RememberedBrowser(
            token_hash=token_hash,
            user_id=user_id,
            expires_at=datetime.fromtimestamp(time.time() + REMEMBERED_BROWSER_TTL_SECONDS, timezone.utc),
        ))
    return {"token": token, "expiresIn": str(REMEMBERED_BROWSER_TTL_SECONDS)}


@app.post("/device/verify")
def verify_remembered_browser(token: str) -> dict[str, str]:
    try:
        payload = serializer.loads(token, max_age=REMEMBERED_BROWSER_TTL_SECONDS)
    except BadSignature as error:
        raise json_error("remembered_browser_invalid", "This remembered browser token is no longer valid.", 401) from error
    with SessionLocal() as session:
        browser = session.get(RememberedBrowser, hashlib.sha256(token.encode()).hexdigest())
        valid = browser is not None and browser.user_id == payload.get("user_id") and as_utc(browser.expires_at) > utc_now()
    if not valid:
        raise json_error("remembered_browser_invalid", "This remembered browser token is no longer valid.", 401)
    return {"userId": payload["user_id"], "next": "done"}


@app.delete("/device")
def forget_browser(token: str, x_user_id: str | None = Header(default=None)) -> None:
    user_id, _ = current_user(x_user_id, None)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with SessionLocal.begin() as session:
        browser = session.get(RememberedBrowser, token_hash)
        if browser is not None and browser.user_id == user_id:
            session.delete(browser)


@app.exception_handler(HTTPException)
async def contract_error_handler(_request: Request, error: HTTPException):
    if isinstance(error.detail, dict) and "error" in error.detail:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=error.status_code, content=error.detail)
    return error