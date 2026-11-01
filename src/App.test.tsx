import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import * as engine from './engine/analyzePassword'

// Partially mock the engine so error paths can be simulated while the real
// implementation still runs for the happy-path tests.
vi.mock('./engine/analyzePassword', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./engine/analyzePassword')>()
  return {
    ...actual,
    analyzePassword: vi.fn(actual.analyzePassword),
  }
})

const analyzePasswordMock = vi.mocked(engine.analyzePassword)

afterEach(() => {
  analyzePasswordMock.mockReset()
})

describe('App', () => {
  it('renders the heading, password field, and Analyze button', () => {
    render(<App />)

    expect(
      screen.getByRole('heading', { level: 1, name: 'Password Analyzer' }),
    ).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Analyze' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Results' })).toBeInTheDocument()
  })

  it('masks the password by default and toggles visibility on Show/Hide', async () => {
    const user = userEvent.setup()
    render(<App />)

    const input = screen.getByLabelText<HTMLInputElement>('Password')
    expect(input.type).toBe('password')

    await user.click(screen.getByRole('button', { name: 'Show' }))
    expect(input.type).toBe('text')
    expect(screen.getByRole('button', { name: 'Hide' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )

    await user.click(screen.getByRole('button', { name: 'Hide' }))
    expect(input.type).toBe('password')
  })

  it('keeps Analyze disabled until a password is entered', async () => {
    const user = userEvent.setup()
    render(<App />)

    const analyzeButton = screen.getByRole<HTMLButtonElement>('button', {
      name: 'Analyze',
    })
    expect(analyzeButton).toBeDisabled()

    await user.type(screen.getByLabelText('Password'), 'hunter2')
    expect(analyzeButton).toBeEnabled()
  })

  it('shows the placeholder before analysis', () => {
    render(<App />)

    expect(
      screen.getByText(/enter a password and select analyze/i),
    ).toBeInTheDocument()
  })

  it('displays analysis results after clicking Analyze', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'password')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    expect(analyzePasswordMock).toHaveBeenCalledWith('password', {
      context: '',
    })
    expect(screen.getByText(/strength: very weak \(0\/4\)/i)).toBeInTheDocument()
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '0')
    expect(
      screen.getByRole('heading', { name: 'Estimated time to crack' }),
    ).toBeInTheDocument()
  })

  it('never renders the password value in the results section', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'Sup3rSecret!')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    const resultsSection = screen
      .getByRole('heading', { name: 'Results' })
      .closest('section')

    expect(resultsSection?.textContent).not.toContain('Sup3rSecret!')
  })

  it('does not log the password to the console during analysis', async () => {
    const user = userEvent.setup()
    const consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
      (method) => vi.spyOn(console, method).mockImplementation(() => undefined),
    )

    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'Sup3rSecret!')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    const loggedValues = consoleSpies.flatMap((spy) => spy.mock.calls.flat())
    expect(
      loggedValues.some((value) => String(value).includes('Sup3rSecret!')),
    ).toBe(false)

    consoleSpies.forEach((spy) => spy.mockRestore())
  })

  it('shows a generic error message when analysis throws', async () => {
    const user = userEvent.setup()
    analyzePasswordMock.mockImplementation(() => {
      throw new Error('internal engine details Sup3rSecret!')
    })

    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'Sup3rSecret!')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    expect(screen.getByRole('alert')).toHaveTextContent(
      /something went wrong while analyzing/i,
    )
    // Raw exception text (which could contain input) must not surface.
    expect(screen.queryByText(/internal engine details/i)).not.toBeInTheDocument()
  })

  it('asks for a password when the engine returns null', async () => {
    const user = userEvent.setup()
    analyzePasswordMock.mockImplementation(() => null)

    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'anything')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    expect(screen.getByRole('alert')).toHaveTextContent(
      /enter a password to analyze/i,
    )
  })

  it('renders an optional personal term field that stays local', async () => {
    const user = userEvent.setup()
    render(<App />)

    const contextInput = screen.getByLabelText(/personal term/i)
    expect(contextInput).toBeInTheDocument()
    expect(
      screen.getByText(/nothing is saved\s*or sent anywhere/i),
    ).toBeInTheDocument()

    await user.type(screen.getByLabelText('Password'), 'Mittens42!')
    await user.type(contextInput, 'mittens')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    expect(analyzePasswordMock).toHaveBeenCalledWith('Mittens42!', {
      context: 'mittens',
    })
  })

  it('renders a weaknesses section with severity labels', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'password')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    expect(screen.getByRole('heading', { name: 'Weaknesses' })).toBeInTheDocument()
    expect(screen.getByText('High')).toBeInTheDocument()
    expect(
      screen.getByText(/appears on lists of commonly used passwords/i),
    ).toBeInTheDocument()
  })

  it('hides the weaknesses section when nothing is found', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'xkCD7#tRq2vLm9pZ')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    expect(
      screen.queryByRole('heading', { name: 'Weaknesses' }),
    ).not.toBeInTheDocument()
  })

  it('never renders the context term in the results section', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'Mittens42!')
    await user.type(screen.getByLabelText(/personal term/i), 'Mittens')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    const resultsSection = screen
      .getByRole('heading', { name: 'Results' })
      .closest('section')

    expect(resultsSection?.textContent).not.toContain('Mittens42!')
  })

  it('clears stale results when the password changes after analyzing', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'password')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(screen.getByRole('progressbar')).toBeInTheDocument()

    // Editing the password must invalidate the displayed analysis.
    await user.type(screen.getByLabelText('Password'), '!')

    expect(
      screen.queryByRole('progressbar'),
    ).not.toBeInTheDocument()
    expect(
      screen.getByText(/enter a password and select analyze/i),
    ).toBeInTheDocument()
  })

  it('clears stale results when the context term changes after analyzing', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'password')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(screen.getByRole('progressbar')).toBeInTheDocument()

    await user.type(screen.getByLabelText(/personal term/i), 'x')

    expect(
      screen.queryByRole('progressbar'),
    ).not.toBeInTheDocument()
  })

  it('resets inputs, results, and returns focus to the password field', async () => {
    const user = userEvent.setup()
    render(<App />)

    const passwordInput = screen.getByLabelText<HTMLInputElement>('Password')
    await user.type(passwordInput, 'password')
    await user.type(screen.getByLabelText(/personal term/i), 'mittens')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(screen.getByRole('progressbar')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Reset' }))

    expect(passwordInput).toHaveValue('')
    expect(screen.getByLabelText(/personal term/i)).toHaveValue('')
    expect(
      screen.queryByRole('progressbar'),
    ).not.toBeInTheDocument()
    expect(
      screen.getByText(/enter a password and select analyze/i),
    ).toBeInTheDocument()
    // Reset is only offered when there is something to reset.
    expect(
      screen.queryByRole('button', { name: 'Reset' }),
    ).not.toBeInTheDocument()
    // Focus returns to the password field for keyboard continuity.
    expect(passwordInput).toHaveFocus()
  })

  it('supports keyboard-only reset via the Reset button', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'password')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    // Reach Reset with the keyboard and activate it with Enter.
    screen.getByRole('button', { name: 'Reset' }).focus()
    await user.keyboard('{Enter}')

    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(
      screen.getByText(/enter a password and select analyze/i),
    ).toBeInTheDocument()
  })

  it('shows a no-findings state when nothing is detected', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'xkCD7#tRq2vLm9pZ')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    expect(screen.getByText(/no specific weaknesses detected/i)).toBeInTheDocument()
    expect(
      screen.queryByRole('heading', { name: 'Weaknesses' }),
    ).not.toBeInTheDocument()
  })

  it('groups weaknesses under descriptive subheadings', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'qwerty123456')
    await user.type(screen.getByLabelText(/personal term/i), 'qwerty')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    expect(screen.getByRole('heading', { name: 'Patterns' })).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Common and personal words' }),
    ).toBeInTheDocument()
  })

  it('shows deduplicated recommendations for detected weaknesses', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'password')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    const heading = screen.getByRole('heading', { name: 'Recommendations' })
    const items = [...heading.parentElement!.querySelectorAll('li')].map(
      (li) => li.textContent ?? '',
    )

    expect(items.length).toBeGreaterThan(0)
    expect(new Set(items).size).toBe(items.length)
  })

  it('rejects a password longer than 256 characters with a clear message', async () => {
    const user = userEvent.setup()
    render(<App />)

    const input = screen.getByLabelText('Password')
    await user.type(input, 'a'.repeat(257))

    expect(
      screen.getByText(/256 characters or fewer/i),
    ).toBeInTheDocument()
    // The engine is never invoked for oversized input.
    expect(analyzePasswordMock).not.toHaveBeenCalled()
    // The button is disabled while oversized.
    expect(screen.getByRole('button', { name: 'Analyze' })).toBeDisabled()
  })

  it('accepts a password of exactly 256 characters', async () => {
    const user = userEvent.setup()
    render(<App />)

    // Avoid typing 256 keystrokes; set the value directly through the input.
    const input = screen.getByLabelText<HTMLInputElement>('Password')
    await user.click(input)
    await user.paste('aB3!'.repeat(64)) // 256 characters

    expect(screen.queryByText(/256 characters or fewer/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Analyze' })).toBeEnabled()
  })

  it('clears stale results when the password becomes oversized', async () => {
    const user = userEvent.setup()
    render(<App />)

    const input = screen.getByLabelText<HTMLInputElement>('Password')
    await user.type(input, 'password')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(screen.getByRole('progressbar')).toBeInTheDocument()

    // Replace the whole value with an oversized one (simulating a paste).
    await user.clear(input)
    await user.paste('x'.repeat(257))

    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
    expect(screen.getByText(/256 characters or fewer/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Analyze' })).toBeDisabled()
  })

  it('does not leak password data in the validation message', async () => {
    const user = userEvent.setup()
    render(<App />)

    const secret = 'Sup3rSecret!'
    const input = screen.getByLabelText('Password')
    await user.type(input, secret.repeat(30))

    const message = screen.getByText(/256 characters or fewer/i).textContent ?? ''
    expect(message).not.toContain('Sup3rSecret')
    expect(message).not.toContain(String(secret.repeat(30).length))
  })

  it('mentions that breach databases are not checked', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Password'), 'password')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))

    expect(
      screen.getByText(/does not\s+currently check breach databases/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/not a guarantee that the password is secure/i),
    ).toBeInTheDocument()
  })
})
