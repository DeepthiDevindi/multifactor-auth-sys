# Review of the Submission 1 Individual Reports

**Group:** Cryptix · **Module:** CS-3053 · **Reviewed on:** 2026-09-21 · **Reviewer:** 230279R (Member 2)

This file lists what is wrong, unclear, or inconsistent in the five individual design reports in this
folder, so that the unified design (Submission 2) can fix it and so each member can correct their own
report if a resubmission is allowed. The unified design that resolves every item below is
`Cryptix_Unified-Design_Submission2.md` / `.pdf` in this folder.

Severity: **High** = factually wrong or breaks another member's design · **Medium** = weakens the
design or misses something the brief asks for · **Low** = wording, numbering, presentation.

## Documents reviewed

| File | Member | Slice | Pages | Diagrams | Assumptions section |
|------|--------|-------|-------|----------|---------------------|
| `230135A_Individual Report.pdf` | M1 — Dewdunika D.R.K.W.M.V.V | Accounts & Factor 1 | 10 | 5 | Yes (A1–A7) |
| `Cryptix_230279R_Jayasinghe-EATD_Factor2-Design.pdf` | M2 — Jayasinghe E.A.T.D | Factor 2 (OTP) | 8 | 6 captioned, **only 2 rendered** | Yes (A1–A12) |
| `230384J (1) (2)_260921_085943.pdf` | M3 — M.D.D. Madhubhashini | Factor 3 (WebAuthn) | 14 | 4 | Yes (bullet list) |
| `230684E_Submission 1.pdf` | M5 — Wansandi M.G.J. | Orchestration & hardening | 5 | **0** | **No** |
| `Samarakoon_S_230562E_Submission1.pdf` | M4 — Samarakoon S.M.S.G. | Accessible client | 11 | 5 | Yes (bullet list) |

The three papers in `../references/` were also read and are used as evidence in the unified design; §5 below says how.

---

## 1. Inconsistencies between reports (must be resolved in the unified design)

These are the places where two members designed the same thing differently. Each has a decision in the
unified design.

| ID | Conflict | Where | Decision taken in the unified design |
|----|----------|-------|---------------------------------------|
| X1 | **Where sessions live and who owns them.** M1 designs a `SESSION` table in the relational database and owns it (M1 Fig. 2, §5). M5 puts all session state in **Redis**, owned by the orchestrator (M5 §3.1). | M1 §5, Fig. 2; M5 §3 | One datastore: PostgreSQL. The `SESSION` row is created by `/login` (M1) but its authentication-state columns are owned by the orchestrator (M5). Redis is not used. M5's atomic "compare-and-consume" is done with a single conditional `UPDATE ... WHERE challenge = ? AND consumed_at IS NULL`, which is atomic in PostgreSQL and gives the same guarantee. |
| X2 | **Recovery email is hashed by M1, but M2 and M5 need to send mail to it.** M1 stores `recovery_email` "hashed at rest" (M1 Fig. 2). A hash cannot be turned back into an address, so M2's email OTP and M5's recovery link both have nowhere to send. | M1 Fig. 2; M2 A3, §5.3; M5 recovery (README) | Store the address **encrypted** (AES-256-GCM, same key hierarchy as the TOTP secret) so it can be recovered for sending, plus an HMAC "blind index" so it can be looked up without decrypting. |
| X3 | **Which edition of NIST SP 800-63B is cited.** M1 and M3 cite Revision 4 (`800-63-4`, §3.x numbering). M2 and M5 cite Revision 3 (`800-63-3`, §5.x numbering). The rules are the same but the section numbers differ, which looks like an error to a marker. | All four | Revision 4 throughout. Rev 3 §5.1.x → Rev 4 §3.1.x; §5.2.x → §3.2.x. |
| X4 | **Lockout numbers.** M1: "N invalid attempts". M2: 5 failures → 15-minute lock, 100 lifetime cap. M5: 1-minute lock, then 14-minute lock. | M1 SR5; M2 §7.2; M5 §5.2 | 5 consecutive failures → lock; lock length doubles from 1 minute to a 15-minute cap; **100 consecutive failures** → locked until recovery (SP 800-63B-4 §3.2.2). Keyed on account **and** source IP. One policy, enforced only by M5's middleware. |
| X5 | **CSRF defence.** The group API contract said `SameSite=Strict` **plus** a CSRF token. M5 §5.3 drops the token and relies on `SameSite` alone. OWASP treats `SameSite` as defence-in-depth, not a sole control. | M5 §5.3 | Both: `SameSite=Strict` cookie **and** a synchroniser token sent in an `X-CSRF-Token` header on every state-changing request. |
| X6 | **Time limits on login steps.** M5 §2.3 sends an expiry time for "the current login step" and offers an extension; M4 decision 4 says "every timed step gets a generous, extendable timeout". M2 §6.2 and M1 AR4 design **no** step timer at all (only the cryptographic ones). | M5 §2.3; M4 D4; M2 §6.2; M1 AR4 | Only the **login session** has an idle timeout (30 min, warned and extendable per WCAG 2.2.1). Individual steps have no timer of their own. Cryptographic lifetimes (TOTP 30 s window, WebAuthn challenge, email code 10 min) are re-issuable, never a dead end. Bhole et al. [ref. folder] report BLV users running out of OTP validity while memorising a code, which is exactly why no extra timer is added. |
| X7 | **HTTP method for WebAuthn options.** M3's Figures 2 and 3 show `GET /webauthn/register/options` and `GET /webauthn/login/options`; M3's Table 2 and the group contract say `POST`. | M3 Fig. 2, Fig. 3, Table 2 | `POST`. The call creates a server-side challenge (a side effect), and `POST` responses are not cached. |
| X8 | **What "Factor 3" means and which factor combinations are allowed.** M3 treats Factor 3 as interchangeable with Factor 2 ("Factor 1 plus one of Factor 2 or Factor 3"). M1's state machine says "after F2 and/or F3". The README never decided. | M3 §2; M1 Fig. 5; README §6 | Login = Factor 1 **plus one** of: WebAuthn (preferred), TOTP, or a backup code — all AAL2. A remembered browser is a convenience, not a factor (changed after review 1). Email OTP opens only a restricted, below-AAL2 recovery session (changed after review 2). See unified design §5. |
| X9 | **Two owners for failed-attempt counters.** M1 stores `failed_factor1_attempts` and `factor1_locked_until` on `USER`; M5's middleware also counts. | M1 Fig. 2, D8; M5 §5.1 | One counter, owned by M5, stored in the `LOGIN_ATTEMPT` table. M1's `USER` columns are removed. |
| X10 | **Stack.** M5 says FastAPI + Redis. M1 says "PostgreSQL/SQLite". M2 says FastAPI + PostgreSQL. README §6 still says `___`. | M5 §1, §3; M1 A5; M2 Fig. 1 | FastAPI + PostgreSQL + plain HTML/JS client. Written into README §6. |
| X11 | **Session-ID rotation.** M1 rotates the session ID at every factor transition (D9). M5 never mentions rotation. | M1 D9; M5 §3 | Rotate on every factor transition and on logout. Owned by M5. |
| X12 | **Sign-counter rule breaks synced passkeys.** M3 §5.5 treats any non-increasing counter as a clone. Synced passkeys (iCloud Keychain, Google Password Manager) always report counter 0, so this rule would reject every one of them. | M3 §5.5, Table 3 | Follow the signature-counter step of WebAuthn Level 2 §7.2: if both the stored and the received counter are 0, the authenticator does not support counters and the check is skipped; otherwise the counter must strictly increase. |
| X13 | **How many steps a login has.** M4's journey map, sequence diagram and spoken prompts assume all three factors run on every login ("Login. Step 1 of 3", "Code accepted. Step 3 of 3: security key"). M3 assumes Factor 1 plus *one* of Factor 2 or 3. | M4 Figs. 1, 3, 4; M3 §2 | Two steps: Factor 1 plus exactly one strong factor (X8). Spoken progress is "Step 1 of 2" / "Step 2 of 2". Toussaint et al. and Bhole et al. [ref. folder] both find that each added step is a real burden for BLV users, so the design never asks for a third. |
| X14 | **Braille and deaf-blind users.** M4 assumes the user is "not someone who is both blind and deaf" and lists braille support as out of scope (§2, §8). M2 A12 requires everything spoken to also exist as DOM text so braille displays work, and M3 assumes "a refreshable Braille display driven by the same accessible DOM". | M4 §2, §8; M2 A12; M3 §2 | Keep M2/M3's rule: all content is real DOM text, so a braille display attached to NVDA or VoiceOver reads it with no extra work by M4. Live-region messages are additionally kept on the page as persistent text, because braille displays show `aria-live` messages only briefly. Deaf-blind users are therefore supported to the extent the screen reader's braille output allows; this is stated as a limitation, not excluded. Toussaint et al. note fewer than 15 % of blind people in France read braille, which is why audio stays the primary channel. |
| X15 | **Speech synthesis "auto-suppressed if a screen reader is detected".** M4 decision 3 and Fig. 5 (`SpeechCueService`) rely on detecting a running screen reader. No web API exposes that; browsers deliberately hide it for privacy. | M4 D3, Fig. 5 | Speech is **opt-in only** (a setting the user turns on), never automatic and never "detected". M4's opt-in half of the decision stands; the detection half is dropped. |

---

## 2. Findings per report

### 2.1 `230135A_Individual Report.pdf` — Member 1, Accounts & Factor 1

Overall: well structured, well referenced, all five artefacts labelled and annotated. Two design errors and a few small items.

| # | Severity | Where | Problem | Fix |
|---|----------|-------|---------|-----|
| M1-1 | **High** | Fig. 2, `USER.recovery_email` "hashed at rest" | A hashed email address cannot be used to send an email. M5's recovery flow and M2's email OTP both need the real address. | Encrypt, do not hash (see X2). |
| M1-2 | **High** | §5, Fig. 2 `SESSION (owned by Member 1)` | Conflicts with M5, who puts sessions in Redis and owns them. Two designs for one thing. | See X1. |
| M1-3 | Medium | Fig. 2, `failed_factor1_attempts`, `factor1_locked_until` | Duplicates M5's lockout counter; D8 says lockout is not enforced locally, but the columns say otherwise. | Remove the columns; see X9. |
| M1-4 | Medium | Fig. 5 | The dashed `POST /logout` arrow from `FullyAuthenticated` appears to end at the `Locked` state. Logout should return to `Unauthenticated`. | Redraw so the arrow ends at `Unauthenticated`. |
| M1-5 | Low | A2 | "the four readers used by 1,539 respondents" — the survey lists more than four readers. | "the four most-used readers in the survey". |
| M1-6 | Low | §12 | Correctly flags that email OTP conflicts with NIST. Good — but the report should say what the group *decided*, not only recommend. | Resolved by X8. |
| M1-7 | Low | Ref. [9] | arXiv:2510.13538 (Oct 2025) — I could not verify this paper exists. Keep only if the group can open the link. | Verify or remove. |

### 2.2 `Cryptix_230279R_Jayasinghe-EATD_Factor2-Design.pdf` — Member 2, Factor 2 (my own report)

Overall: content is complete, but the PDF has a serious rendering defect.

| # | Severity | Where | Problem | Fix |
|---|----------|-------|---------|-----|
| M2-1 | **High** | pp. 4–5, Figures 3, 4, 5, 6 | **Four of the six figures are blank.** The captions are present but the diagrams above them are empty space. Only Figures 1 (component) and 2 (data model) rendered. Cause: the diagram tool gave three diagrams the same internal id, so all but the first rendered as an empty element; the check before export counted diagram tags, not their contents. | Regenerated with a fixed pipeline that refuses to export if any diagram is empty. If Submission 1 can be resubmitted, use the regenerated file. |
| M2-2 | Medium | §5.2, §7.3, DD-08/09/12/15, Ref. [6] | Cites NIST SP 800-63B Revision 3 section numbers (§5.1.3.1, §5.1.2.2, §5.2.2) and URL while M1 and M3 cite Revision 4. | Use Revision 4 (§3.1.3.1, §3.1.2, §3.2.2); see X3. |
| M2-3 | Medium | A3, §5.3 | Assumes `USER.email` is available in plain text. M1 hashes it. | See X2. |
| M2-4 | Medium | §7.2, DD-15 | Lockout numbers differ from M5's. | See X4. |
| M2-5 | Medium | whole report | Does not discuss man-in-the-middle beyond assumption A5 (HTTPS). The brief asks for MITM, replay and cut-and-paste to be addressed explicitly. | Unified design §10.2–10.4. |
| M2-6 | Low | p. 5 | Figure numbering jumps from Figure 2 to Figure 4 in the text; Figure 3's caption is missing (part of M2-1). | Fixed in regeneration. |
| M2-7 | Low | DD-01 | "SMS is classed RESTRICTED by NIST" — true in Rev 3; check the exact wording in Rev 4 before quoting. | Reworded in the unified design as "NIST restricts PSTN/SMS out-of-band use". |

### 2.3 `230384J (1) (2)_260921_085943.pdf` — Member 3, Factor 3 (WebAuthn)

Overall: thorough and well argued, good use of the screen-reader/2FA study. One rule is wrong in a way that matters, plus several consistency items.

| # | Severity | Where | Problem | Fix |
|---|----------|-------|---------|-----|
| M3-1 | **High** | §5.5, Table 3 "Cloned authenticator" | "a non-increasing counter is a hard authentication failure." Synced passkeys always return counter 0 on every use, so this rule rejects every Apple/Google/Microsoft synced passkey — the most accessible authenticators available. | See X12. Skip the check when both counters are 0. |
| M3-2 | Medium | Fig. 2 step 2, Fig. 3 step 2 vs Table 2 | Diagrams say `GET .../options`; the API table and the group contract say `POST`. | Change the diagrams to `POST`; see X7. |
| M3-3 | Medium | Table 2, `POST /webauthn/login/options` — input "username or session hint" | Accepting a bare username lets an attacker learn which usernames have passkeys (the `allowCredentials` list is non-empty). In this system Factor 3 always runs after Factor 1, so a session already exists. | Session only; never username. |
| M3-4 | Medium | §5.1 | "FIDO2/WebAuthn authenticators satisfy [phishing resistance] at both AAL2 and AAL3." Phishing resistance is one AAL3 condition; AAL3 also requires a hardware-based authenticator. A platform/software passkey does not reach AAL3. | "meet the phishing-resistance requirement; AAL3 additionally requires a hardware authenticator". |
| M3-5 | Medium | §6.1–6.2, Figs. 2–3 | The challenge must be tied to the session that requested it. The text says "challenge matches the one issued" but never says where it is stored or that it is single-use per session. | Unified design §10.3: challenge stored on the `SESSION` row, consumed atomically. |
| M3-6 | Low | §9 | The numbered list starts at 6 (6, 7, 8, 9, 10) instead of 1. | Renumber 1–5. |
| M3-7 | Low | Ref. [7] (AFixt) | Listed but never cited in the text. | Cite it or remove it. |
| M3-8 | Low | Fig. 4 "Verify long-lived, rotating device-bound secret" | "Rotating" is never defined (when, how, what happens to the old value). | Unified design §7.3 (trusted device row) and D-20 define it: a new secret is issued on every successful use; the old one is invalidated. |
| M3-9 | Low | Figs. 2–3 | Only the success path is drawn; the failure branches are described in prose (§9). The brief asks for annotated diagrams, so a failure `alt` would strengthen them. | Optional. |

### 2.4 `230684E_Submission 1.pdf` — Member 5, Orchestration, hardening and security evaluation

Overall: the ideas are right (server-side state, atomic consume, temporary lockouts, security headers) but the document is missing most of what the brief asks for, and several details are wrong or conflict with the other reports.

| # | Severity | Where | Problem | Fix |
|---|----------|-------|---------|-----|
| M5-1 | **High** | whole report | **No diagrams.** The brief requires "properly labelled and annotated diagrams". The state machine that is the centre of this slice is described only in prose. | Unified design Figs. 4, 9, 10 and 11 supply the orchestrator state machine, end-to-end login sequence, fallback order and recovery flow. |
| M5-2 | **High** | whole report | **No assumptions section.** The brief says every assumption must be stated. The report silently assumes Redis, FastAPI, a reverse proxy for TLS, and that IP addresses are reliable for rate limiting. | Unified design §2 lists them. |
| M5-3 | **High** | §4.2 | "looks up the session in Redis, compares the challenge and immediately **deletes the record**" — deleting the whole session on consuming a challenge means a user who mistypes one OTP loses the entire login and starts again. Only the *challenge* should be consumed, not the session. | Unified design §10.3: consume the challenge column; the session stays. |
| M5-4 | **High** | §3 | Redis session store conflicts with M1's `SESSION` table. | See X1. |
| M5-5 | Medium | §5.3 | CSRF protection relies on `SameSite=Strict` alone; the group contract required a token as well. | See X5. |
| M5-6 | Medium | §2.3 "Expiration timers" | Per-step expiry with extension conflicts with M1 AR4 and M2 §6.2, and with the README's "no time pressure" principle. | See X6. |
| M5-7 | Medium | missing | The slice per the README also owns the **recovery flow** (`/recovery/start`, `/recovery/verify`), the **audit log** design, `requireFactor(n)`, the **attack test plan** and the **STRIDE table**. None of these is designed; STRIDE is prose with no threat IDs, owners or "tested?" column. | Unified design §10.1 (threat table), §7.5 (recovery), §6 (audit log), §13 (attack tests). |
| M5-8 | Medium | §5.2 | Lockout numbers conflict with M1/M2 and the 100-consecutive-failure cap from NIST is not mentioned even though NIST is cited for the decision. | See X4. |
| M5-9 | Medium | §5.3 HSTS | "Ensures that the browser will only ever connect over HTTPS" — HSTS only applies **after** the first successful HTTPS visit unless the domain is on the preload list. The first visit is still exposed. | Add `preload` and note the first-visit limitation (unified design §10.2, condition C3). |
| M5-10 | Medium | §5.3 | Security-header list is incomplete for an authentication service: no `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, or `Cache-Control: no-store` on authentication responses. | Unified design §10.2 table. |
| M5-11 | Low | §6 Spoofing | "WebAuthn passkeys which are immune to phishing" — the correct term is *phishing-resistant*. Malware on the device, or the trusted-device fallback, can still be attacked. | Reword. |
| M5-12 | Low | §2.3 "Event ID Counter … aligns with ARIA guidelines against screen reader spam" | There is no such ARIA guideline. The relevant material is the WAI-ARIA `aria-live` politeness settings and the APG live-region guidance. The idea itself is good and is kept in the unified design. | Cite WAI-ARIA 1.2 `aria-live` instead. |
| M5-13 | Low | §7 | References have no access dates and are never cited in the text with section numbers, so no statement can be checked against its source. Ref. 2 uses the Rev 3 URL. | Add in-text citations; use Rev 4. |
| M5-14 | Low | header | The title block has no module code, slice name or date. | Add them. |

### 2.5 `Samarakoon_S_230562E_Submission1.pdf` — Member 4, accessible client

Overall: a strong report — two personas, a WCAG 2.2 mapping table, five standard artefacts (journey map, annotated wireframe, sequence, state, component), honest limitations, and a section on where accessibility and security disagreed. The issues are mostly about alignment with the other slices.

| # | Severity | Where | Problem | Fix |
|---|----------|-------|---------|-----|
| M4-1 | **High** | Figs. 1, 3, 4; spoken prompts | Designs a **three-step** login ("Step 1 of 3" … "Step 3 of 3: security key") in which every user does password, then OTP, then passkey. The group policy is Factor 1 plus **one** strong factor. Screens and prompts built on three steps will not match the orchestrator's `next` values. | See X13. Prompts become "Step 1 of 2" / "Step 2 of 2"; the client renders whichever second-factor screen `next` names. |
| M4-2 | Medium | §2 "Who the user is", §8 | Excludes deaf-blind users and treats braille as unbuildable. With semantic HTML the braille display reads the same DOM for free; nothing extra has to be built. Excluding a group the other reports include is an inconsistency, not a scope choice. | See X14. |
| M4-3 | Medium | Decision 3, Fig. 5 `SpeechCueService` "auto-suppressed if AT detected" | There is no browser API that reports whether a screen reader is running. The behaviour cannot be implemented as described. | See X15: opt-in only. |
| M4-4 | Medium | Decision 4 | "Every timed step gets a generous, extendable timeout" contradicts M1 AR4 and M2 §6.2 (no step timers). | See X6. |
| M4-5 | Low | Fig. 2, annotation 2 | "Show characters is a real checkbox … `aria-pressed` reflected." A native checkbox exposes `checked`; `aria-pressed` belongs to toggle *buttons* and would confuse the accessibility tree. | Use a native checkbox with no ARIA state, or a `<button aria-pressed>`; not both. |
| M4-6 | Low | Fig. 4 vs text | Text says `LockedOut` is reachable "from any pending step"; the diagram draws it from `Factor1Pending` and `Factor2Pending` only. | Add the arrow from `Factor3Pending`, or remove the state (the unified design has one `Locked` state, Fig. 3). |
| M4-7 | Low | Ref. [9] | RFC 6238's authors are M'Raihi, Machani, Pei and Rydell — not "Nystrom and Josefsson". | Correct the citation. |
| M4-8 | Low | Ref. [13] (Gaver 1986) | Listed but never cited in the text. | Cite it where "earcons" is used (Fig. 5) or remove it. |
| M4-9 | Low | §2 "Which screen readers" | "NVDA is now the most-used screen reader overall — 65.6 %" is the survey's *commonly used* figure (multiple answers allowed); by *primary* screen reader JAWS still leads. The choice of NVDA is fine; the wording overstates it. | "most commonly used, at 65.6 %". |
| M4-10 | Low | header | No date. | Add it. |
| M4-11 | Low | OTP field (Fig. 3, §5) | Does not mention `autocomplete="one-time-code"` or that paste must not be blocked; M2 AR-2 and M1 AR2 depend on it. | Unified design §9 code-field row. |

What M4 adds that the unified design adopts: the client component split (`FocusManager`, `LiveRegionAnnouncer`, `SpeechCueService`, `ThemeManager`, `APIClient`), the skip link, `aria-describedby` for field errors, the "Show characters" control, persisted theme choice, the WCAG rows for 2.4.7, 2.4.11, 1.4.10, 4.1.2 and 2.5.3, and the test of running with speech turned off entirely.

---

## 3. Things I could not verify

- M1 Ref. [9] (arXiv:2510.13538) and Ref. [1]'s publication date "26 August 2025".
- M3 Ref. [3] (Akanda, Mahdad, Saxena, WWW '25, DOI 10.1145/3696410.3714579). The claims attributed to it are plausible and consistent, but the group should confirm the DOI resolves.
- M2's claim that screen readers read `123456` as a cardinal number is listed in M2's own test plan (T11) as something to confirm with NVDA, not as a fact.

## 4. Checklist against the brief

| Brief requirement | M1 | M2 | M3 | M4 | M5 |
|---|---|---|---|---|---|
| Group name, student ID, name with initials at the top | Yes | Yes | Yes | Yes (no date) | Yes (no module/date) |
| Assumptions clearly stated, none outrageous | Yes | Yes | Yes | Yes | **No section** |
| Own contribution clearly described | Yes | Yes | Yes | Yes | Partly (recovery, audit, tests missing) |
| Standard design artefacts with labelled, annotated diagrams | Yes (5) | 2 of 6 rendered | Yes (4) | Yes (5) | **None** |
| Every decision justified with verifiable facts and references | Yes, in-text with sections | Yes, in-text with sections | Yes, in-text | Yes, in-text | References listed but not cited in text |
| PDF | Yes | Yes | Yes | Yes | Yes |

## 5. External review of the unified design

`../review/MFA_Accessibility_Security_Review.pdf` is an independent review of the **first** version of
the unified design. All eleven of its findings were accepted; unified design §12.1 lists each one with
the change made. The four that change behaviour for other slices:

| Finding | Who is affected | What changed |
|---------|-----------------|--------------|
| The trusted-device cookie is not an AAL2 factor | M3, M5 | Renamed *remembered browser*; a 30-day convenience that skips step 2 on a known browser. Strong factors are WebAuthn and TOTP only. Endpoints are now `/device/remember`, `/device/verify`, `DELETE /device`. |
| Password + email must not bind a new strong factor | M2, M5 | Leaving the restricted session needs an unused backup code, or a 24-hour hold with a cancel link (`/mfa/restricted/unlock`, `/mfa/cancel/{token}`). |
| Backup codes need ≥ 64 bits | M2 | 20 digits (66 bits), five groups of four — M2's individual report said 16. |
| A lost factor must be suspended immediately | M2, M3 | New `.../lost` endpoints suspend at once; deletion waits 24 h behind a cancel link. `suspended_at` columns added. |

For M4: single-character shortcuts are gone (WCAG 2.1.4); every action is a labelled button; target
size (2.5.8), voice control, TalkBack and braille are in the test matrix; the design is described as
built *toward* WCAG 2.2 AA with no AAA claim.

### 5.1 Second review

`../review/Cryptix_MFA_Design_Critical_Review_2.pdf` reviewed the version that followed the first review. Its ten required changes are all in; unified design §12.2 lists them. The ones that change other members' slices:

| Change | Who | What it means |
|--------|-----|---------------|
| Recovery model restated by assurance level | M2, M5 | Password + backup code is a full AAL2 login and needs no special route; the email + 24 h route is kept but declared **below AAL2** (`/mfa/restricted/hold`). |
| Email address must be verified before use | M1 | New `/email/verify` and `/email/resend`; `email_verified_at` column. |
| Emailed code moves from subject to first line of body | M2 | Reverses M2's DD-10 because of lock-screen previews. |
| Report-lost needs more than the password | M2, M3 | `/lost` endpoints take a backup code or emailed code from `Factor1Passed`, or step-up from `Authenticated`. |
| One key per data class | all | `k_totp`, `k_email`, `k_index`, `k_otp_pepper`; `crypto` module gains a key-id parameter. |
| Background worker | M5 | A `JOB` table and a worker process for holds, deletions, expiries and purges. |
| Audit log hardened | M5 | `INSERT`-only role, hash chain, external copy. |
| NIST citations corrected | all | Look-up and out-of-band codes: "at least six decimal digits" (not "20 bits"); Rev 4 does not require encrypted OTP keys; AAL2 timeouts 24 h / 1 h. Anyone citing Rev 3 numbers in their own report should update them. |

## 6. How the `references/` papers are used

| File | Paper | What it supports in the unified design | Caveat |
|------|-------|----------------------------------------|--------|
| `HMI__Accessible_Authentication_for_Users_with_Visu_….pdf` | Usmani, Buhasio, Manduri, Vishwakarma, *Accessible Two Factor Authentication for Users with Visual Impairments*, Frankfurt UAS, 2021 | Blind respondents rated OTP highest of the 2FA methods offered (mean 8.36/10) and face recognition lowest (1.76) → TOTP stays the primary code factor, and no biometric is ever required. Respondents asked for screen readers to read codes **digit by digit** → §9 code-field rule is now evidence, not an assumption. Audio CAPTCHAs called inaccessible → no CAPTCHA. Aural eavesdropping through screen readers → audio-privacy rules. Accessible password managers help → paste and autofill allowed. | A university course report (HMI, June–July 2021), not peer-reviewed; sample size is not stated. Cited for its qualitative findings only. |
| `ecce2025-35.pdf` | Toussaint, Chateau, Gourio-Jewell, Bonnefoy, Louveton, *Inclusive by design: … the ALIAS Project*, ECCE 2025, DOI 10.1145/3746175.3746210 | Each added MFA step is a burden for BLV users → login is Factor 1 plus exactly **one** strong factor, never three (X13). Assistive tools do not preserve privacy in public → never auto-speak, headphone warning. PINs perceived as least secure and most uncomfortable; fingerprint most accessible (citing Faustino & Girouard 2018) → WebAuthn with a platform authenticator preferred; PIN kept only as an alternative to a password. Fewer than 15 % of blind people in France read braille → audio first, braille via DOM text (X14). Nielsen's recognition-over-recall → passkeys and autofill over typed codes. | A position paper describing a planned study; empirical claims are cited through the papers it reviews. |
| `3676509_….pdf` | Bhole, Li, Bokolia, Oh, Tigwell, Peiris, *Haptic2FA*, PACM HCI 8 (MHCI), 2024, DOI 10.1145/3676509 | BLV participants (n = 10) reported running out of OTP validity while memorising the code and that switching apps to fetch a code is the main burden → no added timers, codes re-issuable, autofill, WebAuthn (no app switching). Screen readers reading codes to bystanders → T9. A low-vision participant asked for dark mode → AR-8. Haptic or "match one of three" confirmation is recorded as future work, not adopted. | Study is on Android only, one 1–2 h session, n = 10 (typical for accessibility research, as the authors note). |
