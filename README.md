# Accessible MFA — Multi-Factor Authentication for Visually Impaired Users

Group project for the Computer Security module (Semester 5).

> **Task (as given):** Design and implement a multi-factor authentication system for visually impaired users.

Five members, each owning one slice of the system end to end (design → code → tests → report section), so that individual contribution is clear.

---

## 1. What we are building

A login system that requires more than one factor and can be completed **without sight** — using a screen reader, keyboard, and audio — while still being secure against the usual attacks (credential stuffing, OTP replay, brute force, phishing, session hijacking).

```
[Accessible client]  ──►  [MFA orchestrator]  ──►  Factor 1: password / PIN     (something you know)
 screen-reader-first        decides next factor,    Factor 2: TOTP / email OTP   (something you have)
 audio prompts              lockout, audit log      Factor 3: WebAuthn / passkey (something you have/are)
```

Design principles:

- **Screen-reader first.** Every screen must be completable with the monitor off.
- **Nothing that requires sight only.** No QR-only enrolment, no visual CAPTCHA, no colour-only feedback.
- **No time pressure.** Generous timeouts on every step (WCAG 2.2.1).
- **Secure by default.** Argon2id hashing, rate limiting, lockout, HTTPS, CSRF protection, audit log.

---

## 2. Team and roles

| # | Member | Slice | Owns |
|---|--------|-------|------|
| 1 | vidushi | **Accounts & Factor 1 (knowledge)** | User DB, `/register`, `/login`, `/logout`, sessions, Argon2id password hashing, PIN option for audio keypad entry |
| 2 | thisuri | **Factor 2 (possession: OTP)** | TOTP (RFC 6238) enrol + verify, email OTP alternative, backup codes, secret offered as spoken/copyable text (not QR only) |
| 3 | deepthi_ | **Factor 3 (WebAuthn / passkey)** | WebAuthn register + login ceremonies, credential storage, fallback route when no authenticator is available |
| 4 | sanuji | **Accessible client** | All screens (register, login, enrol, verify, recovery); ARIA, focus order, keyboard-only, Web Speech API prompts, audio cues, high-contrast/large-text mode |
| 5 | januli | **Orchestration, hardening & security evaluation** | Auth state machine (`/auth/status`), shared lockout/rate-limit middleware, audit log, recovery flow, HTTPS, security headers, CSRF, attack tests, STRIDE threat model |

Each member is responsible for their own:

- code (in their area of the repo),
- tests for their slice,
- section of the final report,
- part of the demo.

> Member 3's slice is the technically hardest. Checkpoint date: `___`. If WebAuthn is blocked by then, the fallback is a simpler "trusted device" factor (device-bound secret).

---

## 3. Repository layout

```
.
├── README.md               ← this file
├── docs/
│   ├── api-contract.md     ← every endpoint, request/response — agree this BEFORE coding
│   ├── threat-model.md     ← STRIDE table, owned by Member 5, everyone contributes
│   └── report/             ← one file per member for the final report
├── backend/                ← created once the stack is chosen (see §6)
├── frontend/               ← Member 4
└── tests/                  ← security + accessibility test scripts
```

---

## 4. How we work

1. **Branch per member**: `m1-accounts`, `m2-otp`, `m3-webauthn`, `m4-client`, `m5-orchestration`. `main` is always runnable.
2. **Pull requests** into `main`, reviewed by **one other member** before merge.
3. **Build against the contract.** `docs/api-contract.md` is the source of truth. Member 4 builds the UI against a mock server so the front end is not blocked by the back end.
4. **Commit messages**: short, present tense, prefixed with your slice — e.g. `m2: add TOTP verify endpoint`.
5. **Never commit secrets.** `.env` is git-ignored; put example values in `.env.example`.

---

## 5. Milestones

| Phase | What | Done when | Date |
|-------|------|-----------|------|
| 0 | Kick-off meeting | Stack, deadline, factor set decided; `api-contract.md` written; everyone has cloned the repo | `___` |
| 1 | Parallel build | Each slice works on its own against the contract | `___` |
| 2 | Integration checkpoint (~60% of time) | Full login runs end to end with **NVDA** and the monitor off | `___` |
| 3 | Evaluation | Member 5 runs attack tests, Member 4 runs accessibility audit, everyone fixes their slice | `___` |
| 4 | Report + demo | Each member's section written; demo walks through every factor | `___` |

---

## 6. Decisions still to make (kick-off meeting)

| Decision | Options | Chosen |
|----------|---------|--------|
| Stack | React + TypeScript + Vite frontend; backend remains a separate implementation owned by the server contributors. | React client selected for the accessible client |
| Deadline | From module handbook | `___` |
| Factor set | Default: password/PIN + TOTP/email OTP + WebAuthn | `___` |
| Which factors are mandatory vs optional per login | e.g. F1 + one of F2/F3 | `___` |
| Demo format | Live / recorded / none | `___` |

---

## 7. Testing

- **Security** (Member 5): brute force on F1/F2, OTP replay, session fixation, CSRF, skipping a factor by calling a protected endpoint directly, OWASP ZAP baseline scan.
- **Accessibility** (Member 4): every flow completed with NVDA (free, Windows) with the monitor off; keyboard-only run; axe / Lighthouse scan; WCAG 2.2 AA checklist.
- **Unit tests** (everyone): for your own slice, in `tests/`.

---

## 8. Running the project

The accessible client lives in `frontend/` and currently uses local mock behavior while the backend is developed against the API contract.

```bash
cd frontend
npm install
npm run dev
```

The backend boundary is kept in `backend/`; backend contributors should implement the endpoints in `docs/api-contract.md` there without moving client code.

---

## 9. References

- RFC 6238 — TOTP: <https://www.rfc-editor.org/rfc/rfc6238>
- WebAuthn Level 2: <https://www.w3.org/TR/webauthn-2/>
- WCAG 2.2: <https://www.w3.org/TR/WCAG22/>
- NVDA screen reader: <https://www.nvaccess.org/>
- OWASP Authentication Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
