import { describe, expect, it, vi } from 'vitest'
import {
  analyzePassword,
  mapStrengthLabel,
  MAX_PASSWORD_LENGTH,
  PasswordTooLongError,
} from './analyzePassword'

// A high-entropy, non-dictionary password.
const STRONG_PASSWORD = 'v9#Qm2!xLp7$Rt4@Wy6&Zn3'
// A predictable, patterned password.
const PREDICTABLE_PASSWORD = 'Summer2026!'

describe('analyzePassword', () => {
  it('returns null for an empty password', () => {
    expect(analyzePassword('')).toBeNull()
  })

  it('rates a common password as Very Weak (score 0)', () => {
    const result = analyzePassword('password')

    expect(result).not.toBeNull()
    expect(result?.score).toBe(0)
    expect(result?.label).toBe('Very Weak')
  })

  it('rates a predictable password as weak to fair', () => {
    const result = analyzePassword(PREDICTABLE_PASSWORD)

    expect(result).not.toBeNull()
    expect(result?.score).toBeLessThanOrEqual(2)
  })

  it('rates a long unpredictable password as Very Strong (score 4)', () => {
    const result = analyzePassword(STRONG_PASSWORD)

    expect(result).not.toBeNull()
    expect(result?.score).toBe(4)
    expect(result?.label).toBe('Very Strong')
  })

  it('keeps the label consistent with the score', () => {
    for (const password of ['password', 'hunter2', PREDICTABLE_PASSWORD, STRONG_PASSWORD]) {
      const result = analyzePassword(password)
      expect(result?.label).toBe(mapStrengthLabel(result?.score ?? -1))
    }
  })

  it('extracts warnings and suggestions for a weak password', () => {
    const result = analyzePassword('password')

    expect(result?.warnings.length).toBeGreaterThan(0)
    expect(result?.suggestions.length).toBeGreaterThan(0)
  })

  it('provides crack-time estimates for every scenario', () => {
    const result = analyzePassword('password')

    expect(result?.crackTimeEstimates.onlineThrottled).toBe('2 minutes')
    expect(result?.crackTimeEstimates.onlineUnthrottled).toBe('less than a second')
    expect(result?.crackTimeEstimates.offlineSlowHashing).toBe('less than a second')
    expect(result?.crackTimeEstimates.offlineFastHashing).toBe('less than a second')
  })

  it('never retains the original password in the sanitized result', () => {
    // Use distinctive passwords: generic words like "password" may appear in
    // zxcvbn's feedback text itself (e.g. "top-10 common password"), which is
    // advice, not leaked input.
    for (const password of [
      'hunter2',
      PREDICTABLE_PASSWORD,
      STRONG_PASSWORD,
      'correct-horse-battery-staple-9271',
    ]) {
      const result = analyzePassword(password)
      const serialized = JSON.stringify(result)

      expect(result).not.toHaveProperty('password')
      expect(serialized).not.toContain(password)
    }
  })

  it('does not log the password to the console', () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const
    const spies = methods.map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    )

    analyzePassword('Sup3rSecret!')

    const logged = spies.flatMap((spy) => spy.mock.calls.flat())
    expect(logged.some((value) => String(value).includes('Sup3rSecret!'))).toBe(false)

    spies.forEach((spy) => spy.mockRestore())
  })

  it('throws a RangeError for out-of-range scores', () => {
    expect(() => mapStrengthLabel(-1)).toThrow(RangeError)
    expect(() => mapStrengthLabel(5)).toThrow(RangeError)
    expect(() => mapStrengthLabel(2.5)).toThrow(RangeError)
  })

  it('maps every score to the expected label', () => {
    expect(mapStrengthLabel(0)).toBe('Very Weak')
    expect(mapStrengthLabel(1)).toBe('Weak')
    expect(mapStrengthLabel(2)).toBe('Fair')
    expect(mapStrengthLabel(3)).toBe('Strong')
    expect(mapStrengthLabel(4)).toBe('Very Strong')
  })
})

describe('analyzePassword findings', () => {
  it('reports a common password as a high-severity finding', () => {
    const result = analyzePassword('password')

    expect(result?.findings.map((f) => f.category)).toContain('common-password')
    expect(
      result?.findings.find((f) => f.category === 'common-password')?.severity,
    ).toBe('high')
  })

  it('reports numeric and keyboard patterns together', () => {
    const result = analyzePassword('qwerty123456')
    const categories = result?.findings.map((f) => f.category) ?? []

    expect(categories).toContain('keyboard-pattern')
    expect(categories).toContain('numeric-sequence')
  })

  it('reports repeated characters', () => {
    const result = analyzePassword('aaa111!')

    expect(result?.findings.map((f) => f.category)).toContain(
      'repeated-character',
    )
  })

  it('sorts findings most severe first', () => {
    const result = analyzePassword('qwerty123456')
    const severities = result?.findings.map((f) => f.severity) ?? []
    const rank = { high: 0, medium: 1, low: 2 } as const

    for (let i = 1; i < severities.length; i += 1) {
      expect(rank[severities[i - 1]]).toBeLessThanOrEqual(rank[severities[i]])
    }
  })

  it('produces no findings for a strong random password', () => {
    const result = analyzePassword(STRONG_PASSWORD)

    expect(result?.findings).toEqual([])
  })

  it('flags a password containing the supplied context term', () => {
    const result = analyzePassword('Mittens42!', { context: 'mittens' })

    expect(result?.findings.map((f) => f.category)).toContain(
      'personal-context',
    )
  })

  it('does not flag context when the term is absent', () => {
    const result = analyzePassword('zzz9999!', { context: 'mittens' })

    expect(result?.findings.map((f) => f.category)).not.toContain(
      'personal-context',
    )
  })

  it('treats a missing context option the same as no context', () => {
    const without = analyzePassword('zzz9999!')
    const withEmpty = analyzePassword('zzz9999!', { context: '' })

    expect(withEmpty?.findings).toEqual(without?.findings)
  })

  it('never leaks the password, a sequence, or the context term into findings', () => {
    const cases: Array<[string, string | undefined]> = [
      ['qwerty123456', undefined],
      ['aaa111!', undefined],
      ['Mittens42!', 'mittens'],
      ['abcabc123', undefined],
    ]

    for (const [password, context] of cases) {
      const result = analyzePassword(password, { context })
      const serialized = JSON.stringify(result)

      expect(serialized).not.toContain(password)
      if (context !== undefined) {
        expect(serialized.toLowerCase()).not.toContain(context.toLowerCase())
      }
    }
  })

  it('does not log findings containing the password', () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const
    const spies = methods.map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    )

    analyzePassword('qwerty123456', { context: 'qwerty' })

    const logged = spies.flatMap((spy) => spy.mock.calls.flat())
    expect(logged.some((value) => String(value).includes('qwerty'))).toBe(false)

    spies.forEach((spy) => spy.mockRestore())
  })

  it('keeps existing score and crack-time behaviour unchanged', () => {
    const result = analyzePassword('password')

    expect(result?.score).toBe(0)
    expect(result?.label).toBe('Very Weak')
    expect(result?.crackTimeEstimates.onlineThrottled).toBe('2 minutes')
    expect(result?.warnings.length).toBeGreaterThan(0)
    expect(result?.suggestions.length).toBeGreaterThan(0)
  })

  it('returns null for empty input even with context supplied', () => {
    expect(analyzePassword('', { context: 'mittens' })).toBeNull()
  })

  it('never repeats an identical suggestion or recommendation', () => {
    for (const password of [
      'password',
      'qwerty123456',
      'aaa111!',
      PREDICTABLE_PASSWORD,
      STRONG_PASSWORD,
    ]) {
      const result = analyzePassword(password)

      expect(new Set(result?.suggestions).size).toBe(result?.suggestions.length)
      expect(new Set(result?.recommendations).size).toBe(
        result?.recommendations.length,
      )
    }
  })

  it('includes a recommendation for each detected weakness category', () => {
    const result = analyzePassword('qwerty123456')

    expect(result?.recommendations).toContain(
      'Avoid straight keyboard rows; combine characters from different rows.',
    )
    expect(result?.recommendations).toContain(
      'Break up ascending or descending digit runs with unrelated digits.',
    )
  })

  it('gives no recommendations for a strong password with no findings', () => {
    const result = analyzePassword(STRONG_PASSWORD)

    expect(result?.findings).toEqual([])
    expect(result?.recommendations).toEqual([])
  })

  it('never puts the password, a substring, or the context term in recommendations', () => {
    const result = analyzePassword('qwerty123456', { context: 'qwerty' })
    const serialized = JSON.stringify(result?.recommendations)

    expect(serialized).not.toContain('qwerty123456')
    expect(serialized.toLowerCase()).not.toContain('qwerty')
  })
})

describe('analyzePassword length limit', () => {
  it('exports the documented maximum of 256', () => {
    expect(MAX_PASSWORD_LENGTH).toBe(256)
  })

  it('still returns null for empty input', () => {
    expect(analyzePassword('')).toBeNull()
  })

  it('analyzes a password of exactly the maximum length', () => {
    const input = 'aB3!'.repeat(64) // 256 characters
    expect(input.length).toBe(MAX_PASSWORD_LENGTH)

    const result = analyzePassword(input)

    expect(result).not.toBeNull()
    expect(result?.score).toBeGreaterThanOrEqual(0)
    expect(result?.score).toBeLessThanOrEqual(4)
  })

  it('rejects a password one character over the maximum', () => {
    const input = 'aB3!'.repeat(64) + 'x' // 257 characters
    expect(input.length).toBe(MAX_PASSWORD_LENGTH + 1)

    expect(() => analyzePassword(input)).toThrow(PasswordTooLongError)
  })

  it('rejects very long pasted input without hanging', () => {
    // ~2,000 characters previously caused a ~79 second delay (F-1).
    const input = 'a1!'.repeat(700)

    expect(() => analyzePassword(input)).toThrow(PasswordTooLongError)
  })

  it('counts length in UTF-16 code units, so emoji count as two', () => {
    // U+1F600 is a surrogate pair: 2 UTF-16 code units.
    const base = '🔐'.repeat(128) // 256 code units, 128 code points
    expect(base.length).toBe(MAX_PASSWORD_LENGTH)
    expect(() => analyzePassword(base)).not.toThrow()

    const over = base + '🔐' // 258 code units
    expect(over.length).toBe(MAX_PASSWORD_LENGTH + 2)
    expect(() => analyzePassword(over)).toThrow(PasswordTooLongError)
  })

  it('handles combining characters at the boundary', () => {
    // Explicit base + combining acute: each grapheme is 2 UTF-16 code units.
    const combining = 'e\u0301'
    const base = combining.repeat(128)
    expect(base.length).toBe(MAX_PASSWORD_LENGTH)
    expect(() => analyzePassword(base)).not.toThrow()

    expect(() => analyzePassword(base + combining)).toThrow(PasswordTooLongError)
  })

  it('never invokes zxcvbn for oversized input', async () => {
    // zxcvbn is CommonJS; under vitest its callable form is on `.default`.
    const ns = (await vi.importActual('zxcvbn')) as Record<string, unknown>
    const actual = ns.default
    if (typeof actual !== 'function') {
      throw new Error('expected zxcvbn default export to be a function')
    }
    const spy = vi.fn(actual as (password: string) => unknown)
    vi.doMock('zxcvbn', () => ({ default: spy }))

    try {
      // Re-import so the mocked zxcvbn is bound to the module under test.
      const mod = await import('./analyzePassword')

      expect(() => mod.analyzePassword('a1!'.repeat(700))).toThrow(
        mod.PasswordTooLongError,
      )
      expect(spy).not.toHaveBeenCalled()
    } finally {
      vi.doUnmock('zxcvbn')
    }
  })

  it('does not leak password data through the validation error', () => {
    const secret = 'Sup3rSecret!'.repeat(30)
    let message = ''

    try {
      analyzePassword(secret)
    } catch (error) {
      message = error instanceof Error ? error.message : String(error)
    }

    expect(message).not.toContain('Sup3rSecret')
    expect(message).not.toContain(String(secret.length))
  })

  it('does not log the password when rejecting oversized input', () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const
    const spies = methods.map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    )

    expect(() => analyzePassword('Sup3rSecret!'.repeat(30))).toThrow()

    const logged = spies.flatMap((spy) => spy.mock.calls.flat())
    expect(logged.some((value) => String(value).includes('Sup3rSecret'))).toBe(false)

    spies.forEach((spy) => spy.mockRestore())
  })

  it('does not truncate oversized input silently', () => {
    // A truncated-and-analyzed result would return a value; rejection throws.
    expect(() => analyzePassword('a'.repeat(300))).toThrow(PasswordTooLongError)
  })
})
