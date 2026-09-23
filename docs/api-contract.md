# API Contract

Source of truth for every endpoint. **Agree this before writing code.** Member 4 builds the client against this; Members 1, 2, 3, 5 implement it.

Conventions (fill in at kick-off):

- Base URL: `___`
- Auth: session cookie (`httpOnly`, `Secure`, `SameSite=Strict`) — set by Member 1, checked by Member 5's middleware
- Error shape: `{ "error": "<machine_code>", "message": "<human readable, will be read aloud>" }`
- Every error `message` must make sense when spoken by a screen reader with no visual context.

---

## Member 1 — Accounts & Factor 1

| Method | Path | Request | Response | Notes |
|--------|------|---------|----------|-------|
| POST | `/register` | `{ email, username?, password \| pin }` | `201 { userId }` | Email is the unique account identifier; Argon2id; enforce policy |
| POST | `/login` | `{ email, password \| pin }` | `200 { next: "factor2" \| "factor3" \| "done" }` | Email is used for lookup; calls M5 rate limiter |
| POST | `/logout` | – | `204` | |
| GET | `/me` | – | `200 { userId, username, factorsEnrolled: [...] }` | Requires full auth |

## Member 2 — Factor 2 (OTP)

| Method | Path | Request | Response | Notes |
|--------|------|---------|----------|-------|
| POST | `/mfa/totp/enroll` | – | `200 { secret, otpauthUri, spokenSecret }` | Secret also as grouped text for TTS |
| POST | `/mfa/totp/verify` | `{ code }` | `200 { next }` | ±1 step window; max 5 attempts |
| POST | `/mfa/email/send` | – | `202` | |
| POST | `/mfa/email/verify` | `{ code }` | `200 { next }` | |
| POST | `/mfa/backup/generate` | – | `200 { codes: [...] }` | Shown/spoken once |
| POST | `/mfa/backup/verify` | `{ code }` | `200 { next }` | Single use |

## Member 3 — Factor 3 (WebAuthn)

| Method | Path | Request | Response | Notes |
|--------|------|---------|----------|-------|
| POST | `/webauthn/register/options` | – | `200 PublicKeyCredentialCreationOptions` | |
| POST | `/webauthn/register/verify` | attestation response | `200 { credentialId }` | |
| POST | `/webauthn/login/options` | – | `200 PublicKeyCredentialRequestOptions` | |
| POST | `/webauthn/login/verify` | assertion response | `200 { next }` | Verify origin, challenge, counter |

## Member 5 — Orchestration & recovery

| Method | Path | Request | Response | Notes |
|--------|------|---------|----------|-------|
| GET | `/auth/status` | – | `200 { state, next, factorsDone: [...] }` | State machine |
| POST | `/recovery/start` | `{ username }` | `202` | Email link/code |
| POST | `/recovery/verify` | `{ code, newPassword }` | `200` | |
| – | `/audit` (internal) | – | – | Log every auth event |

Middleware (used by all): `rateLimit(key, maxAttempts, window)`, `lockout(userId)`, `requireFactor(n)`.

---

## Client screens (Member 4)

| Screen | Calls | Spoken prompt on load |
|--------|-------|-----------------------|
| Register | `/register` | "Create an account. Enter your email address." |
| Login – step 1 | `/login` | |
| Login – OTP | `/mfa/totp/verify` or `/mfa/email/verify` | "Put on headphones if you are in public." |
| Login – passkey | `/webauthn/login/*` | "Touch your security key or use your fingerprint." |
| Enrol factors | `/mfa/totp/enroll`, `/webauthn/register/*` | |
| Recovery | `/recovery/*` | |
