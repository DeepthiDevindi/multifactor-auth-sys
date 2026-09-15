# Threat Model (STRIDE)

Owner: Member 5. Each member adds the rows for their own slice.

## Assets

- User credentials (password/PIN hashes, TOTP secrets, WebAuthn public keys)
- Session tokens
- OTPs in transit (email, spoken aloud)
- Audit log

## Trust boundaries

- Browser ↔ server (HTTPS)
- Server ↔ database
- Server ↔ email provider
- User ↔ surroundings (audio can be overheard)

## Threats

| ID | Category | Threat | Affects | Mitigation | Owner | Tested? |
|----|----------|--------|---------|------------|-------|---------|
| T1 | Spoofing | Credential stuffing / password guessing | F1 | Argon2id, rate limit, lockout | M1 / M5 | |
| T2 | Spoofing | OTP brute force | F2 | 6-digit code, 5 attempts, lockout | M2 / M5 | |
| T3 | Spoofing | Phishing of OTP | F2 | Encourage F3 (phishing-resistant); short OTP lifetime | M2 | |
| T4 | Spoofing | Phishing of WebAuthn | F3 | Origin binding in WebAuthn | M3 | |
| T5 | Tampering | Skip a factor by calling protected endpoint directly | All | `requireFactor(n)` middleware; server-side state machine | M5 | |
| T6 | Repudiation | User denies a login | All | Audit log with timestamp, IP, factor results | M5 | |
| T7 | Info disclosure | OTP read aloud is overheard | F2 | Headphone prompt before TTS; option to not speak the code | M4 | |
| T8 | Info disclosure | Database leak | F1, F2 | Argon2id hashes; TOTP secrets encrypted at rest | M1 / M2 | |
| T9 | Info disclosure | Session token theft (XSS) | All | `httpOnly` cookie, CSP header | M1 / M5 | |
| T10 | DoS | Lockout used to lock a victim out | All | Lockout keyed on user + IP; recovery path | M5 | |
| T11 | Elevation | OTP replay | F2 | Single-use codes; track last used counter | M2 | |
| T12 | Elevation | Session fixation | All | Rotate session ID after each factor | M1 / M5 | |
| T13 | Elevation | CSRF | All | `SameSite=Strict` + CSRF token | M5 | |
| T14 | Spoofing | Cloned WebAuthn authenticator | F3 | Signature counter check | M3 | |

Add rows as you find new threats. Column "Tested?" is filled in during Phase 3.

## Out of scope

_List what we deliberately do not defend against (e.g. compromised OS, malicious screen reader extension) and why._
