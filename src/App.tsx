import { useRef, useState, type FormEvent } from 'react'
import PasswordInput from './components/PasswordInput'
import Results from './components/Results'
import {
  analyzePassword,
  MAX_PASSWORD_LENGTH,
  PasswordTooLongError,
  type AnalysisResult,
} from './engine/analyzePassword'

function App(): React.JSX.Element {
  const [password, setPassword] = useState('')
  const [context, setContext] = useState('')
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [hasAnalyzed, setHasAnalyzed] = useState(false)
  const passwordInputRef = useRef<HTMLInputElement>(null)

  // Oversized input is rejected before analysis. The message is static and
  // never contains the password or any derived data.
  const isTooLong = password.length > MAX_PASSWORD_LENGTH
  const validationError = isTooLong
    ? `Passwords must be ${MAX_PASSWORD_LENGTH} characters or fewer to analyze. Please shorten it and try again.`
    : null

  /** Returns the UI to the pre-analysis state. Never touches stored data. */
  function clearResults(): void {
    setAnalysis(null)
    setError(null)
    setHasAnalyzed(false)
  }

  // Stale results are cleared as soon as either input changes, so the results
  // section never describes a password that is no longer in the field.
  function handlePasswordChange(value: string): void {
    setPassword(value)
    clearResults()
  }

  function handleContextChange(value: string): void {
    setContext(value)
    clearResults()
  }

  function handleReset(): void {
    setPassword('')
    setContext('')
    clearResults()
    // Return focus to the first field so keyboard users can continue directly.
    passwordInputRef.current?.focus()
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault()

    // Guard here as well as in the engine, so oversized input never reaches
    // analysis and stale results are cleared immediately.
    if (isTooLong) {
      setAnalysis(null)
      setHasAnalyzed(false)
      setError(validationError)
      return
    }

    try {
      const result = analyzePassword(password, { context })
      setAnalysis(result)
      // Clear any previous error. The message never includes the password.
      setError(result === null ? 'Enter a password to analyze.' : null)
      setHasAnalyzed(true)
    } catch (error) {
      // Oversized input is a validation problem, not an unexpected failure.
      if (error instanceof PasswordTooLongError) {
        setAnalysis(null)
        setError(validationError)
        setHasAnalyzed(true)
        return
      }
      // Never surface exception details: they could carry input values.
      setAnalysis(null)
      setError('Something went wrong while analyzing. Please try again.')
      setHasAnalyzed(true)
    }
  }

  const canReset = password.length > 0 || context.length > 0 || hasAnalyzed

  return (
    <main className="app">
      <h1>Password Analyzer</h1>
      <p className="app__subtitle">
        Check how guessable a password is. Everything runs in your browser — your
        password never leaves this device.
      </p>

      <form className="app__form" onSubmit={handleSubmit}>
        <PasswordInput
          value={password}
          onChange={handlePasswordChange}
          inputRef={passwordInputRef}
          error={validationError}
        />

        <div className="context-field">
          <label htmlFor="context-term">Personal term (optional)</label>
          <input
            id="context-term"
            type="text"
            value={context}
            onChange={(event) => handleContextChange(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            aria-describedby="context-hint"
            placeholder="e.g. a name or pet's name"
          />
          <p id="context-hint" className="context-field__hint">
            Optional. Checked against the password in your browser only.
            Nothing is saved or sent anywhere.
          </p>
        </div>

        <div className="app__actions">
          <button
            type="submit"
            className="button button--primary"
            disabled={password.length === 0 || isTooLong}
          >
            Analyze
          </button>
          {canReset && (
            <button
              type="button"
              className="button button--secondary"
              onClick={handleReset}
            >
              Reset
            </button>
          )}
        </div>
      </form>

      <Results hasAnalyzed={hasAnalyzed} analysis={analysis} error={error} />
    </main>
  )
}

export default App
