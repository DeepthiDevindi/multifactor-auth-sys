import { FormEvent, useEffect, useState } from 'react'

type View = 'login' | 'register' | 'recovery' | 'otp' | 'passkey' | 'enroll' | 'success'

const steps = ['Account', 'Verification', 'Access']

function isStrongPassword(value: string) {
  return value.length >= 12 && /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value) && /[^A-Za-z0-9]/.test(value)
}

function isValidEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim())
}

function passwordRequirements(value: string) {
  return [
    value.length >= 12,
    /[a-z]/.test(value),
    /[A-Z]/.test(value),
    /\d/.test(value),
    /[^A-Za-z0-9]/.test(value),
  ]
}

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:4000'

function base64UrlToBuffer(value: string) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4)
  const binary = window.atob(padded)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer
}

function bufferToBase64Url(value: ArrayBuffer | null) {
  if (!value) return null
  const bytes = new Uint8Array(value)
  let binary = ''
  bytes.forEach((byte) => { binary += String.fromCharCode(byte) })
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function sessionId() {
  const key = 'cryptix-session-id'
  const existing = window.sessionStorage.getItem(key)
  if (existing) return existing
  const created = crypto.randomUUID()
  window.sessionStorage.setItem(key, created)
  return created
}

function App() {
  const [view, setView] = useState<View>('login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [emailPurpose, setEmailPurpose] = useState<'login' | 'registration'>('login')
  const [message, setMessage] = useState('')
  const [largeText, setLargeText] = useState(false)
  const [highContrast, setHighContrast] = useState(false)
  const [speakPrompts, setSpeakPrompts] = useState(false)

  useEffect(() => {
    if (!speakPrompts || !('speechSynthesis' in window)) return
    const prompt = view === 'otp'
      ? 'Verification code. Enter the six digit code sent to your device.'
      : view === 'passkey'
        ? 'Passkey verification. Use your fingerprint, face, or security key.'
        : view === 'register'
          ? 'Create an account. Enter a username.'
          : 'Sign in to Beacon.'
    window.speechSynthesis.cancel()
    window.speechSynthesis.speak(new SpeechSynthesisUtterance(prompt))
  }, [speakPrompts, view])

  async function submitAccount(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    if (!isValidEmail(email) || !password || (view === 'register' && (!username.trim() || !isStrongPassword(password)))) {
      if (view === 'register' && password && !isStrongPassword(password)) {
        setMessage('Choose a stronger password. It must have at least 12 characters, including uppercase, lowercase, a number, and a symbol.')
        return
      }
      setMessage(!isValidEmail(email) ? 'Enter a valid email address so we can send your verification code.' : view === 'register' ? 'Enter your username, email address, and password to continue.' : 'Enter your email address and password to continue.')
      return
    }
    try {
      const purpose = view === 'register' ? 'registration' : 'login'
      setEmailPurpose(purpose)
      const response = await fetch(`${API_BASE_URL}/mfa/email/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-User-Email': email, 'X-Session-Id': sessionId() },
        body: JSON.stringify({ email, purpose }),
      })
      const result = await response.json().catch(() => null)
      if (!response.ok) throw new Error(result?.message ?? 'Email delivery could not be completed.')
      setCode('')
      setMessage(`A verification code was sent to ${email}.`)
      setView('otp')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The verification email could not be sent. Try again.')
    }
  }

  async function submitCode(event: FormEvent) {
    event.preventDefault()
    if (!/^\d{6}$/.test(code)) {
      setMessage('Enter the six digit verification code.')
      return
    }
    try {
      const response = await fetch(`${API_BASE_URL}/mfa/email/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-User-Email': email, 'X-Session-Id': sessionId() },
        body: JSON.stringify({ email, code, purpose: emailPurpose }),
      })
      const result = await response.json().catch(() => null)
      if (!response.ok) throw new Error(result?.message ?? 'That code is not valid. Check the email and try again.')
      setMessage('Email verified. Your account is ready.')
      setView('success')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'That code could not be verified. Try again.')
    }
  }

  function startRecovery(event: FormEvent) {
    event.preventDefault()
    setMessage('If an account matches, recovery instructions will be sent shortly.')
  }

  async function resendCode() {
    try {
      const response = await fetch(`${API_BASE_URL}/mfa/email/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-User-Email': email, 'X-Session-Id': sessionId() },
        body: JSON.stringify({ email, purpose: emailPurpose }),
      })
      const result = await response.json().catch(() => null)
      if (!response.ok) throw new Error(result?.message ?? 'The new verification email could not be sent.')
      setCode('')
      setMessage(`A new verification code was sent to ${email}.`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The new verification email could not be sent.')
    }
  }

  async function startPasskeyLogin() {
    setMessage('Requesting a passkey challenge. Follow your browser or device prompt.')
    if (!window.PublicKeyCredential || !navigator.credentials) {
      setMessage('This browser does not support passkeys. Choose a verification code instead.')
      return
    }
    try {
      const headers = { 'X-Session-Id': sessionId(), 'X-User-Email': email || 'demo@example.com' }
      const optionsResponse = await fetch(`${API_BASE_URL}/webauthn/login/options`, { method: 'POST', headers })
      if (!optionsResponse.ok) throw new Error('options')
      const options = await optionsResponse.json()
      if (!options.allowCredentials?.length) {
        setMessage('No passkey is registered for this account yet. Register a passkey first, or choose a verification code instead.')
        return
      }
      const credential = await navigator.credentials.get({
        publicKey: {
          ...options,
          challenge: base64UrlToBuffer(options.challenge),
          allowCredentials: (options.allowCredentials ?? []).map((allowed: { id: string; type?: string; transports?: AuthenticatorTransport[] }) => ({
            ...allowed,
            id: base64UrlToBuffer(allowed.id),
          })),
        },
      }) as PublicKeyCredential | null
      if (!credential) throw new Error('cancelled')
      const assertion = credential.response as AuthenticatorAssertionResponse
      const verificationResponse = await fetch(`${API_BASE_URL}/webauthn/login/verify`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: credential.id,
          rawId: bufferToBase64Url(credential.rawId),
          response: {
            clientDataJSON: bufferToBase64Url(assertion.clientDataJSON),
            authenticatorData: bufferToBase64Url(assertion.authenticatorData),
            signature: bufferToBase64Url(assertion.signature),
            userHandle: bufferToBase64Url(assertion.userHandle),
          },
          type: credential.type,
        }),
      })
      if (!verificationResponse.ok) {
        const errorBody = await verificationResponse.json().catch(() => null)
        throw new Error(errorBody?.message ?? 'verification')
      }
      setMessage('')
      setView('success')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : ''
      setMessage(errorMessage === 'cancelled' ? 'Passkey verification was cancelled. You can try again or use a verification code.' : errorMessage && errorMessage !== 'options' && errorMessage !== 'verification' ? errorMessage : 'Passkey verification could not be completed. Check that the backend is running and try again.')
    }
  }

  async function startPasskeyEnrollment() {
    setMessage('Requesting passkey registration. Follow your browser or device prompt.')
    if (!window.PublicKeyCredential || !navigator.credentials) {
      setMessage('This browser does not support passkeys. Use a supported browser or security key.')
      return
    }
    try {
      const headers = { 'X-Session-Id': sessionId(), 'X-User-Email': email || 'demo@example.com' }
      const optionsResponse = await fetch(`${API_BASE_URL}/webauthn/register/options`, { method: 'POST', headers })
      if (!optionsResponse.ok) throw new Error('options')
      const options = await optionsResponse.json()
      const credential = await navigator.credentials.create({
        publicKey: {
          ...options,
          challenge: base64UrlToBuffer(options.challenge),
          user: { ...options.user, id: base64UrlToBuffer(options.user.id) },
          excludeCredentials: (options.excludeCredentials ?? []).map((excluded: { id: string; type?: string; transports?: AuthenticatorTransport[] }) => ({
            ...excluded,
            id: base64UrlToBuffer(excluded.id),
          })),
        },
      }) as PublicKeyCredential | null
      if (!credential) throw new Error('cancelled')
      const attestation = credential.response as AuthenticatorAttestationResponse
      const verificationResponse = await fetch(`${API_BASE_URL}/webauthn/register/verify`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: credential.id,
          rawId: bufferToBase64Url(credential.rawId),
          response: {
            clientDataJSON: bufferToBase64Url(attestation.clientDataJSON),
            attestationObject: bufferToBase64Url(attestation.attestationObject),
            transports: attestation.getTransports?.() ?? [],
          },
          type: credential.type,
        }),
      })
      if (!verificationResponse.ok) {
        const errorBody = await verificationResponse.json().catch(() => null)
        throw new Error(errorBody?.message ?? 'verification')
      }
      setMessage('Passkey registered successfully. You can now use it to sign in.')
      setView('success')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : ''
      setMessage(errorMessage === 'cancelled' ? 'Passkey registration was cancelled. You can try again.' : errorMessage && errorMessage !== 'options' && errorMessage !== 'verification' ? errorMessage : 'Passkey registration could not be completed. Check that the backend is running and try again.')
    }
  }

  const activeStep = view === 'login' || view === 'register' ? 0 : view === 'success' ? 2 : 1

  return (
    <main className={`app-shell ${largeText ? 'large-text' : ''} ${highContrast ? 'high-contrast' : ''}`}>
      <header className="topbar">
        <a className="brand" href="/" aria-label="Beacon home">
          <span className="brand-mark" aria-hidden="true">B</span>
          <span>beacon</span>
        </a>
        <button className="text-button" type="button" onClick={() => setView(view === 'register' ? 'login' : 'register')}>
          {view === 'register' ? 'Sign in' : 'Create account'}
        </button>
      </header>

      <section className="workspace" aria-labelledby="page-title">
        <div className="intro">
          <p className="eyebrow">Accessible identity</p>
          <h1 id="page-title">Your account,<br /><em>within reach.</em></h1>
          <p className="intro-copy">Beacon protects every sign-in with clear, patient steps designed for keyboard and screen reader users.</p>
          <div className="trust-note"><span aria-hidden="true">●</span><span>Private by design. Your verification details stay yours.</span></div>
        </div>

        <div className="auth-panel">
          <div className="progress" aria-label={`Step ${activeStep + 1} of 3: ${steps[activeStep]}`}>
            {steps.map((step, index) => <div className={`progress-step ${index <= activeStep ? 'active' : ''}`} key={step}><span>{index + 1}</span>{step}</div>)}
          </div>

          {view === 'login' || view === 'register' ? <AccountForm view={view} username={username} email={email} password={password} message={message} setUsername={setUsername} setEmail={setEmail} setPassword={setPassword} onSubmit={submitAccount} onRecovery={() => { setMessage(''); setView('recovery') }} /> : null}
          {view === 'recovery' ? <RecoveryForm message={message} onSubmit={startRecovery} onBack={() => { setMessage(''); setView('login') }} /> : null}
          {view === 'otp' ? <OtpForm email={email} code={code} message={message} setCode={setCode} onSubmit={submitCode} onResend={resendCode} onPasskey={() => { setMessage(''); setView('passkey') }} /> : null}
          {view === 'passkey' ? <PasskeyScreen message={message} onBack={() => { setMessage(''); setView('otp') }} onStart={startPasskeyLogin} /> : null}
          {view === 'enroll' ? <PasskeyEnrollmentScreen message={message} onBack={() => { setMessage(''); setView('success') }} onStart={startPasskeyEnrollment} /> : null}
          {view === 'success' ? <SuccessScreen username={username} message={message} onEnroll={() => { setMessage(''); setView('enroll') }} onReset={() => { setPassword(''); setCode(''); setMessage(''); setView('login') }} /> : null}
        </div>
      </section>

      <footer className="settings" aria-label="Accessibility settings">
        <span className="settings-label">Accessibility</span>
        <label><input type="checkbox" checked={speakPrompts} onChange={(event) => setSpeakPrompts(event.target.checked)} /> Speak prompts</label>
        <label><input type="checkbox" checked={largeText} onChange={(event) => setLargeText(event.target.checked)} /> Large text</label>
        <label><input type="checkbox" checked={highContrast} onChange={(event) => setHighContrast(event.target.checked)} /> High contrast</label>
      </footer>
    </main>
  )
}

type AccountFormProps = { view: 'login' | 'register'; username: string; email: string; password: string; message: string; setUsername: (value: string) => void; setEmail: (value: string) => void; setPassword: (value: string) => void; onSubmit: (event: FormEvent) => void; onRecovery: () => void }
function AccountForm({ view, username, email, password, message, setUsername, setEmail, setPassword, onSubmit, onRecovery }: AccountFormProps) {
  const register = view === 'register'
  const requirements = passwordRequirements(password)
  return <div className="form-content">
    <p className="section-kicker">{register ? 'New here?' : 'Welcome back'}</p>
    <h2>{register ? 'Create your account' : 'Sign in securely'}</h2>
    <p className="form-help">{register ? 'You will verify your identity in the next step.' : 'Use your Beacon credentials to continue.'}</p>
    <form onSubmit={onSubmit} noValidate>
      {register && <><label htmlFor="username">Display name</label><input id="username" autoComplete="nickname" value={username} onChange={(event) => setUsername(event.target.value)} /></>}
      <label htmlFor="email">Email address</label>
      <input id="email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} />
      <label htmlFor="password">Password</label>
      <input id="password" type="password" autoComplete={register ? 'new-password' : 'current-password'} value={password} onChange={(event) => setPassword(event.target.value)} />
      {register && <ul className="password-requirements" aria-label="Password requirements">
        <li className={requirements[0] ? 'met' : ''}>At least 12 characters</li>
        <li className={requirements[1] ? 'met' : ''}>A lowercase letter</li>
        <li className={requirements[2] ? 'met' : ''}>An uppercase letter</li>
        <li className={requirements[3] ? 'met' : ''}>A number</li>
        <li className={requirements[4] ? 'met' : ''}>A symbol</li>
      </ul>}
      {message && <p className="form-message" role="status">{message}</p>}
      <button className="primary-button" type="submit">{register ? 'Create account' : 'Continue'} <span aria-hidden="true">→</span></button>
    </form>
    {!register && <button className="link-button" type="button" onClick={onRecovery}>Forgot your password?</button>}
  </div>
}

function RecoveryForm({ message, onSubmit, onBack }: { message: string; onSubmit: (event: FormEvent) => void; onBack: () => void }) {
  return <div className="form-content"><p className="section-kicker">Account recovery</p><h2>Find your account</h2><p className="form-help">We will send a recovery code to the verified contact on your account.</p><form onSubmit={onSubmit}><label htmlFor="recovery-username">Username</label><input id="recovery-username" autoComplete="username" />{message && <p className="form-message" role="status">{message}</p>}<button className="primary-button" type="submit">Send recovery code <span aria-hidden="true">→</span></button></form><button className="link-button" type="button" onClick={onBack}>Back to sign in</button></div>
}

function OtpForm({ email, code, message, setCode, onSubmit, onResend, onPasskey }: { email: string; code: string; message: string; setCode: (value: string) => void; onSubmit: (event: FormEvent) => void; onResend: () => void; onPasskey: () => void }) {
  return <div className="form-content"><p className="section-kicker">Step 2 of 3 · Verification</p><h2>Check your device</h2><p className="form-help">A six digit code was sent to {email}. Enter it here. Take your time.</p><form onSubmit={onSubmit}><label htmlFor="otp">Verification code</label><input id="otp" inputMode="numeric" pattern="[0-9]*" autoComplete="one-time-code" maxLength={6} value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ''))} />{message && <p className="form-message" role="alert">{message}</p>}<button className="primary-button" type="submit">Verify code <span aria-hidden="true">→</span></button></form><div className="alternate"><span>Have a passkey?</span><button className="link-button" type="button" onClick={onPasskey}>Use passkey instead</button></div><p className="quiet-note">Need another code? <button className="inline-button" type="button" onClick={onResend}>Send a new one</button></p></div>
}

function PasskeyScreen({ message, onBack, onStart }: { message: string; onBack: () => void; onStart: () => void }) {
  return <div className="form-content passkey-content"><p className="section-kicker">Step 2 of 3 · Passkey</p><div className="passkey-icon" aria-hidden="true">⌁</div><h2>Use your passkey</h2><p className="form-help">Touch your security key, or use the fingerprint or face sensor on your device.</p>{message && <p className="form-message" role="status">{message}</p>}<button className="primary-button" type="button" onClick={() => void onStart()}>Continue with passkey <span aria-hidden="true">→</span></button><button className="link-button" type="button" onClick={onBack}>Use a verification code instead</button></div>
}

function PasskeyEnrollmentScreen({ message, onBack, onStart }: { message: string; onBack: () => void; onStart: () => void }) {
  return <div className="form-content passkey-content"><p className="section-kicker">Secure your account</p><div className="passkey-icon" aria-hidden="true">⌁</div><h2>Register a passkey</h2><p className="form-help">Your device will create a passkey. Your private key stays on your device and is never sent to Beacon.</p>{message && <p className="form-message" role="status">{message}</p>}<button className="primary-button" type="button" onClick={() => void onStart()}>Register passkey <span aria-hidden="true">→</span></button><button className="link-button" type="button" onClick={onBack}>Back</button></div>
}

function SuccessScreen({ username, message, onEnroll, onReset }: { username: string; message: string; onEnroll: () => void; onReset: () => void }) {
  return <div className="form-content success-content"><div className="success-icon" aria-hidden="true">✓</div><p className="section-kicker">Verified</p><h2>Welcome{username ? `, ${username}` : ''}.</h2><p className="form-help">{message || 'Your identity has been confirmed and your secure session is ready.'}</p><button className="primary-button" type="button" onClick={onEnroll}>Register a passkey <span aria-hidden="true">→</span></button><button className="link-button" type="button" onClick={onReset}>Return to sign in</button></div>
}

export default App