import { describe, expect, it } from 'vitest'
import {
  detectContext,
  detectKeyboardPatterns,
  detectRepeats,
  detectSequences,
  findingsFromFeedback,
  severityLabel,
} from './patterns'

describe('detectRepeats', () => {
  it('flags a single character repeated three or more times', () => {
    const findings = detectRepeats('aaa')

    expect(findings.map((f) => f.category)).toContain('repeated-character')
    // The explanation reports the length only, never the character.
    expect(findings[0].explanation).toContain('3 times')
    expect(findings[0].explanation).not.toContain('aaa')
  })

  it('escalates severity for a long repeated character run', () => {
    const short = detectRepeats('aaabbb')
    const long = detectRepeats('aaaaaabbb')

    expect(short[0].severity).toBe('medium')
    expect(long[0].severity).toBe('high')
  })

  it('flags a repeated sequence', () => {
    const findings = detectRepeats('abcabc123')

    expect(findings.map((f) => f.category)).toContain('repeated-sequence')
  })

  it('does not flag two repeated characters', () => {
    expect(detectRepeats('password')).toEqual([])
    expect(detectRepeats('aabb')).toEqual([])
  })

  it('does not repeat the character or sequence in the explanation', () => {
    const findings = detectRepeats('aaaaaa')
    const serialized = JSON.stringify(findings)

    // A six-character run of one character must not leak that character as a
    // six-character substring, and no finding may contain the password.
    expect(serialized).not.toContain('aaaaaa')
  })
})

describe('detectSequences', () => {
  it('flags an ascending numeric sequence', () => {
    const findings = detectSequences('123456')

    expect(findings.map((f) => f.category)).toContain('numeric-sequence')
    expect(findings[0].severity).toBe('high')
  })

  it('flags a descending numeric sequence', () => {
    expect(detectSequences('987654').map((f) => f.category)).toContain(
      'numeric-sequence',
    )
  })

  it('flags an ascending alphabetic sequence', () => {
    const findings = detectSequences('abcdef')

    expect(findings.map((f) => f.category)).toContain('alphabetic-sequence')
  })

  it('flags a descending alphabetic sequence', () => {
    expect(detectSequences('fedcba').map((f) => f.category)).toContain(
      'alphabetic-sequence',
    )
  })

  it('does not flag a sequence shorter than four characters', () => {
    expect(detectSequences('123')).toEqual([])
    expect(detectSequences('abc')).toEqual([])
  })

  it('does not flag non-consecutive digits', () => {
    expect(detectSequences('1357924680')).toEqual([])
  })

  it('does not expose the sequence itself in the explanation', () => {
    const serialized = JSON.stringify(detectSequences('12345678'))

    expect(serialized).not.toContain('12345678')
    expect(serialized).not.toContain('1234')
  })
})

describe('detectKeyboardPatterns', () => {
  it('flags a straight keyboard run', () => {
    const findings = detectKeyboardPatterns('qwerty')

    expect(findings.map((f) => f.category)).toContain('keyboard-pattern')
    expect(findings[0].severity).toBe('high')
  })

  it('flags a home-row run', () => {
    expect(detectKeyboardPatterns('asdfgh').map((f) => f.category)).toContain(
      'keyboard-pattern',
    )
  })

  it('flags a reversed keyboard run', () => {
    expect(detectKeyboardPatterns('ytrewq').map((f) => f.category)).toContain(
      'keyboard-pattern',
    )
  })

  it('does not flag letters that merely share a keyboard row', () => {
    // "ipp" sits on the top row but is not an adjacent run.
    expect(detectKeyboardPatterns('mississippi')).toEqual([])
  })

  it('does not expose the keyboard run in the explanation', () => {
    const serialized = JSON.stringify(detectKeyboardPatterns('qwertyuiop'))

    expect(serialized).not.toContain('qwerty')
  })
})

describe('findingsFromFeedback', () => {
  it('classifies a common-password warning as high severity', () => {
    const findings = findingsFromFeedback('This is a top-10 common password')

    expect(findings).toHaveLength(1)
    expect(findings[0].category).toBe('common-password')
    expect(findings[0].severity).toBe('high')
  })

  it('classifies a similar-to-common warning as a predictable word', () => {
    const findings = findingsFromFeedback(
      'This is similar to a commonly used password',
    )

    expect(findings[0].category).toBe('predictable-word')
    expect(findings[0].severity).toBe('medium')
  })

  it('returns nothing for an empty warning', () => {
    expect(findingsFromFeedback('')).toEqual([])
  })

  it('returns nothing for an unrecognised warning rather than guessing', () => {
    expect(findingsFromFeedback('Something else entirely')).toEqual([])
  })
})

describe('detectContext', () => {
  it('flags a password containing the supplied term, case-insensitively', () => {
    const findings = detectContext('John1234!', 'john')

    expect(findings).not.toBeNull()
    expect(findings).toEqual([
      {
        category: 'personal-context',
        severity: 'high',
        explanation:
          'This password contains the personal term you provided, which attackers can guess.',
      },
    ])
  })

  it('returns an empty list when the term is absent', () => {
    expect(detectContext('zzz9999', 'john')).toEqual([])
  })

  it('returns null when no term was supplied', () => {
    expect(detectContext('zzz9999', undefined)).toBeNull()
    expect(detectContext('zzz9999', '   ')).toBeNull()
  })

  it('never includes the term in the explanation', () => {
    const serialized = JSON.stringify(detectContext('mycatmittens', 'Mittens'))

    expect(serialized).not.toContain('Mittens')
    expect(serialized).not.toContain('mittens')
  })
})

describe('severityLabel', () => {
  it('maps every severity to a display label', () => {
    expect(severityLabel('high')).toBe('High')
    expect(severityLabel('medium')).toBe('Medium')
    expect(severityLabel('low')).toBe('Low')
  })
})
