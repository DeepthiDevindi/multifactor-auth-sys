# Backend boundary

The backend is intentionally kept separate from the client work. This folder contains Deepthi's passkey/security-key service, implementing the endpoints in [`docs/api-contract.md`](../docs/api-contract.md). The combined design assigns passkeys to Factor 2, even though the earlier repository README labels the slice Factor 3.

The implementation uses Python, FastAPI, SQLAlchemy, PostgreSQL, and the `webauthn` package. The database schema is created on startup with these tables:

- `passkey_credentials`: public keys, signature counters, transports, and lost timestamps
- `webauthn_challenges`: session-bound, purpose-bound, single-use challenges
- `remembered_browsers`: hashed browser tokens with expiry

M1/M5 should provide authenticated session identity and the unique email identity instead of the development `X-User-Id`, `X-User-Email`, and `X-Session-Id` headers.

## Run locally

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 4000
```

Create the PostgreSQL database and user, then set `DATABASE_URL` in `.env` using the format in `.env.example`. Set `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN` when the client is not running at the local defaults. For a local ORM smoke test only, `DATABASE_URL=sqlite:///./validation.db` is also supported.

Email verification requires an SMTP provider. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM` in `.env`. For Gmail, use `smtp.gmail.com`, port `587`, and an app password rather than your normal account password. The service will return a clear configuration error until these values are present.