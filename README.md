# Accessible MFA — Multi-Factor Authentication for Visually Impaired Users

Group project for CS-3053 Computer Security (Semester 5). Group **Cryptix**.

> **Task (as given):** Design and implement a multi-factor authentication system for visually impaired users.

Five members, each owning one slice of the system end to end (design → code → tests → report section), so that individual contribution is clear.

The agreed design is the unified design report: `documents/Cryptix_Unified-Design_Submission2.md` (source) and `documents/Unified-Design_Submission2.pdf` (submitted PDF). Section numbers below refer to that report.

---

## 1. What we are building

A web login system that needs **two different kinds of proof** and can be completed **without sight**, using a screen reader, a keyboard and audio.

```
 User's side                                  Authentication server (HTTPS only)
 ───────────                                  ──────────────────────────────────
 User with screen reader ──┐
 or braille display        │                  Orchestrator (M5)
                           ├─► Browser: ───►  login state machine, lockout,
 Authenticator app ·······┘   accessible      audit log, recovery
 (user types/pastes code)     client (M4)         │
                                ▲                 ├─► Accounts + Factor 1 (M1)   password / PIN     ── something the user KNOWS
 Passkey / security key ────────┘                 ├─► OTP factor (M2)           authenticator-app  ── something the user HAS
 (signs the challenge)                            │                             code, emailed codes,
                                                  │                             backup codes
                                                  └─► Passkey factor (M3)       passkey / security ── something the user HAS
                                                                                key, remembered browser
                                                        │
                                                   Database  (users, second factors, sessions, backup codes, audit log)
```

**Normal login (§4.5):** username + password/PIN → Factor 1 verified → authenticator-app OTP **or** passkey/security key → Factor 2 verified → Authenticated. Two steps, never three.

**Supporting mechanisms (§4.6):** backup codes (password + backup code is still a full login), a restricted email-code recovery route with a 24-hour waiting period, lockout, an audit log, and "remember this browser" for 30 days (a convenience, **not** a factor).

Design principles:

- **Screen-reader first.** Every screen must be completable with the monitor off.
- **Nothing that requires sight only.** No QR-only set-up, no visual CAPTCHA, no colour-only feedback, no drag-and-drop-only action, no screen that moves on by itself.
- **No time pressure.** No timers on login steps; the session warns two minutes before it expires.
- **Secrets are never spoken automatically.** A silent alternative (copy, direct link) always exists.
- **Secure by default.** Salted Argon2id hashing, fresh single-use challenges bound to session and purpose, session ID replaced after each step, lockout, HTTPS, audit log.

Attacks the design is analysed against (§6): password guessing, replay, man-in-the-middle, cut-and-paste, interleaving, session misuse, bypassing the second factor, eavesdropping on spoken secrets.

---

## 2. Team and roles

| # | Member | Student ID | Slice | Owns |
|---|--------|-----------|-------|------|
| M1 | Dewdunika D.R.K.W.M.V.V (vidushi) | 230135A | **Accounts & Factor 1 (knowledge)** | User records, `/register`, `/login`, `/logout`, session records, Argon2id password/PIN hashing, email confirmation |
| M2 | Jayasinghe E.A.T.D (thisuri) | 230279R | **Factor 2: OTP (possession)** | TOTP (RFC 6238) set-up + verify, secret offered as link / copyable text / speech (never QR-only), emailed codes, backup codes |
| M3 | Madhubhashini M.D.D. (deepthi_) | 230384J | **Factor 2: passkey / security key (possession)** | WebAuthn register + login ceremonies, public-key storage, report-lost, "remember this browser" |
| M4 | Samarakoon S.M.S.G. (sanuji) | 230562E | **Accessible client** | All screens (register, set-up, login, recovery, manage factors); screen-reader announcements, keyboard-only operation, braille-safe text, optional speech output, large text, high contrast |
| M5 | Wansandi M.G.J. (januli) | 230684E | **Orchestration, hardening & security evaluation** | Login state machine (`/auth/status`), lockout, audit log, recovery flow and 24-hour waiting period, HTTPS/security headers, security tests, STRIDE-style analysis |

Each member is responsible for their own:

- code (in their area of the repo),
- tests for their slice,
- section of the final report,
- part of the demo.

> M3's slice is the technically hardest. Checkpoint date: `___`. If passkeys are blocked by then, the authenticator-app OTP (M2) is already the other Factor 2 option, so no new factor is needed. "Remember this browser" stays a convenience and is never counted as a factor (§4.6).

---

## 3. Repository layout

```
.
├── README.md                                   ← this file
├── documents/
│   ├── Cryptix_Unified-Design_Submission2.md   ← the agreed design (Submission 2), Markdown source
│   ├── Unified-Design_Submission2.pdf          ← the same, as submitted
│   ├── README.md                               ← internal review of the five individual reports
│   └── *.pdf                                   ← the five individual designs (Submission 1)
├── references/                                 ← papers used in the design
├── review/                                     ← external review notes (internal use only)
├── backend/                                    ← FastAPI app (to be built, see §6)
├── frontend/                                   ← Member 4, plain HTML/JS client (to be built)
└── tests/                                      ← security + accessibility tests (to be built)
```

---

## 4. How we work

1. **Branch per member**: `m1-accounts`, `m2-otp`, `m3-webauthn`, `m4-client`, `m5-orchestration`. `main` is always runnable.
2. **Pull requests** into `main`, reviewed by **one other member** before merge.
3. **Build against the design.** The API summary is Appendix B of the unified design and the data model is §8.4. Member 4 builds the UI against a mock server so the front end is not blocked by the back end.
4. **Commit messages**: short, present tense, prefixed with your slice — e.g. `m2: add TOTP verify endpoint`.
5. **Never commit secrets or virtual environments.** `.env` and `.venv/` are git-ignored; put example values in `.env.example`.

---

## 5. Milestones

| Phase | What | Done when | Date |
|-------|------|-----------|------|
| 0 | Kick-off meeting | Stack, deadline, factor set decided; unified design agreed; everyone has cloned the repo | done (2026-09-21) |
| 1 | Parallel build | Each slice works on its own against Appendix B | `___` |
| 2 | Integration checkpoint (~60% of time) | Full login runs end to end with **NVDA** and the monitor off | `___` |
| 3 | Evaluation | M5 runs the security tests (§10.1), M4 runs the accessibility tests (§10.2), everyone fixes their slice | `___` |
| 4 | Report + demo | Each member's section written; demo walks through every factor | `___` |

---

## 6. Decisions (from the unified design)

| Decision | Chosen | Where |
|----------|--------|-------|
| Stack | **FastAPI + PostgreSQL backend, React + TypeScript + Vite client**, no Redis; cryptography only from established libraries | §3, D1 |
| Factor 1 | Password (8+ chars) or numeric PIN (6+ digits), checked against a common-password list, stored as a salted Argon2id hash | §4.2, D2 |
| Factor 2 | Authenticator-app OTP **or** passkey / security key (passkey preferred); ten single-use backup codes as support | §4.3, D3 |
| What a login needs | Factor 1 **plus exactly one** strong second factor. Password + backup code is a full login. Emailed code opens only a restricted session and can add a new factor only after a 24-hour waiting period with a cancel link | §4.1, §5.4, D4, D8 |
| Challenges and codes | Fresh random challenge per login, bound to session and purpose, accepted once; every one-time value single-use | §6.2, D5 |
| Sessions | Random session ID, state on the server, ID replaced after each step, 30 min idle / 12 h absolute, deleted at logout; sensitive changes need Factor 2 again within 5 min | §4.7, D6, D7 |
| Lockout | 5 wrong → 1 min lock doubling to 15 min; 100 total → locked until recovery; counted per account and per address | §5.3, D9 |
| Accessibility | Secret as link / text / speech, codes read digit by digit, no timers, no single-letter shortcuts, large text and high contrast | §7, D9 |
| Storage | Hash what is only checked; encrypt (keys outside the DB) what must be recovered; append-only audit log | §8, D10 |
| Deadline | From module handbook | `___` |
| Demo format | Live / recorded / none | `___` |

---

## 7. Testing

Test IDs are those of the unified design, §10. **Nothing has been run yet; every test is Planned.**

- **Security** (M5): ST-1 to ST-11 — correct login, wrong password + lockout, wrong / reused OTP, replayed passkey answer, cut-and-paste and interleaving attempts, skipping Factor 2, session expiry / logout / fixation, man-in-the-middle (untrusted certificate, plain HTTP, look-alike site), recovery routes.
- **Accessibility** (M4): AT-1 to AT-6 — every flow with NVDA and the monitor off; keyboard only; VoiceOver, TalkBack, braille display and voice control; error messages; passkey and OTP set-up without a QR code; automated scan plus 200 % / 400 % zoom and high contrast.
- **Unit tests** (everyone): for your own slice, in `tests/`.

Testing with blind and low-vision participants is planned but has not been done (§11).

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

- Unified design report: `documents/Cryptix_Unified-Design_Submission2.md` (full reference list at the end of that document)
- RFC 6238 — TOTP: <https://www.rfc-editor.org/rfc/rfc6238>
- WebAuthn Level 3: <https://www.w3.org/TR/webauthn-3/>
- WCAG 2.2: <https://www.w3.org/TR/WCAG22/>
- NVDA screen reader: <https://www.nvaccess.org/>
- OWASP Authentication Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- OWASP Session Management Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
