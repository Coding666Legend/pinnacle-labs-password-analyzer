import { useId, useState, type RefObject } from 'react'

interface PasswordInputProps {
  value: string
  onChange: (value: string) => void
  /** Optional external ref, used by the parent to restore focus after reset. */
  inputRef?: RefObject<HTMLInputElement | null>
  /** Validation message shown below the field. Never contains password data. */
  error?: string | null
}

function PasswordInput({
  value,
  onChange,
  inputRef,
  error = null,
}: PasswordInputProps): React.JSX.Element {
  const [isVisible, setIsVisible] = useState(false)
  const inputId = useId()
  const errorId = useId()
  const hasError = error !== null

  return (
    <div className="password-input">
      <label htmlFor={inputId}>Password</label>
      <div className="password-input__row">
        <input
          id={inputId}
          ref={inputRef}
          type={isVisible ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          placeholder="Enter a password to analyze"
          aria-invalid={hasError}
          aria-describedby={hasError ? errorId : undefined}
        />
        <button
          type="button"
          className="button button--secondary"
          aria-pressed={isVisible}
          onClick={() => setIsVisible((visible) => !visible)}
        >
          {isVisible ? 'Hide' : 'Show'}
        </button>
      </div>
      {hasError && (
        <p id={errorId} className="password-input__error" role="alert">
          {error}
        </p>
      )}
    </div>
  )
}

export default PasswordInput
