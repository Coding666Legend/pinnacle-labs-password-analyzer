/**
 * Additional pattern detection layered on top of zxcvbn.
 *
 * These detectors explain *why* a password is predictable in plain language.
 * Every finding is sanitized: it carries a category, an explanation, and a
 * severity, but never the matched substring, its position, or the password.
 */

export type FindingCategory =
  | 'repeated-character'
  | 'repeated-sequence'
  | 'numeric-sequence'
  | 'alphabetic-sequence'
  | 'keyboard-pattern'
  | 'common-password'
  | 'predictable-word'
  | 'personal-context'

export type Severity = 'low' | 'medium' | 'high'

export interface Finding {
  category: FindingCategory
  severity: Severity
  /** Human-readable explanation. Never contains the password or a substring. */
  explanation: string
}

/** Keyboard rows used for adjacency-independent run detection. */
const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm']

/** Minimum run length before a repeated character is worth reporting. */
const MIN_REPEAT_LENGTH = 3

/** Minimum length of a repeated sequence worth reporting (e.g. "abab" -> 2). */
const MIN_REPEATED_SEQ_LENGTH = 2

/** Minimum run length before a numeric/alphabetic sequence is reported. */
const MIN_SEQUENCE_LENGTH = 4

/** Minimum run length before a keyboard row run is reported. */
const MIN_KEYBOARD_LENGTH = 4

/** Longest run of a single character worth reporting before escalating. */
const LONG_REPEAT_LENGTH = 5

const SEVERITY_LABEL: Readonly<Record<Severity, string>> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
}

/** Human-readable severity for display. */
export function severityLabel(severity: Severity): string {
  return SEVERITY_LABEL[severity]
}

/**
 * Detects runs of the same character (e.g. "aaaa") and repeated sequences
 * (e.g. "abcabc"). Reports counts and lengths only — never the characters.
 */
export function detectRepeats(password: string): Finding[] {
  const findings: Finding[] = []

  const singleRun = longestRun(password, (a, b) => a === b)
  if (singleRun.length >= MIN_REPEAT_LENGTH) {
    findings.push({
      category: 'repeated-character',
      severity: singleRun.length >= LONG_REPEAT_LENGTH ? 'high' : 'medium',
      explanation: `Contains a single character repeated ${singleRun.length} times in a row, which attackers try first.`,
    })
  }

  const repeatedSequence = longestRepeatedSequence(password)
  if (repeatedSequence !== null && repeatedSequence >= MIN_REPEATED_SEQ_LENGTH) {
    findings.push({
      category: 'repeated-sequence',
      severity: 'medium',
      explanation: `Repeats a ${repeatedSequence}-character sequence, which makes the password shorter than it looks.`,
    })
  }

  return findings
}

/** Detects ascending/descending numeric and alphabetic runs ("12345", "abcd"). */
export function detectSequences(password: string): Finding[] {
  const findings: Finding[] = []

  const numericRun = longestDirectionalRun(password, (char) =>
    isNumeric(char) ? char.charCodeAt(0) : null,
  )
  if (numericRun.length >= MIN_SEQUENCE_LENGTH) {
    findings.push({
      category: 'numeric-sequence',
      severity: 'high',
      explanation: `Contains ${numericRun.length} ascending or descending digits in a row (a common sequence attackers guess early).`,
    })
  }

  const alphaRun = longestDirectionalRun(password, (char) =>
    isAlphabetic(char) ? char.charCodeAt(0) : null,
  )
  if (alphaRun.length >= MIN_SEQUENCE_LENGTH) {
    findings.push({
      category: 'alphabetic-sequence',
      severity: 'medium',
      explanation: `Contains ${alphaRun.length} consecutive letters of the alphabet in order.`,
    })
  }

  return findings
}

/** Detects straight keyboard runs such as "qwerty" or "asdfgh". */
export function detectKeyboardPatterns(password: string): Finding[] {
  const lower = password.toLowerCase()
  let best = 0

  for (const row of KEYBOARD_ROWS) {
    const run = longestDirectionalRun(lower, (char) => {
      const index = row.indexOf(char)
      return index === -1 ? null : index
    })
    if (run.length > best) best = run.length
  }

  if (best < MIN_KEYBOARD_LENGTH) return []

  return [
    {
      category: 'keyboard-pattern',
      severity: 'high',
      explanation: `Contains a straight keyboard run of ${best} characters from the same key row, which attackers try early.`,
    },
  ]
}

/**
 * Turns zxcvbn's single feedback warning into structured findings.
 *
 * zxcvbn already detects common passwords and dictionary words internally, so
 * we classify its warning rather than maintaining a redundant word list.
 */
export function findingsFromFeedback(warning: string): Finding[] {
  if (warning.length === 0) return []

  const lower = warning.toLowerCase()

  if (lower.includes('common password')) {
    return [
      {
        category: 'common-password',
        severity: 'high',
        explanation: 'This password appears on lists of commonly used passwords.',
      },
    ]
  }

  if (
    lower.includes('similar to a commonly used password') ||
    lower.includes('a common name') ||
    lower.includes('first name') ||
    lower.includes('last name')
  ) {
    return [
      {
        category: 'predictable-word',
        severity: 'medium',
        explanation:
          'This password resembles a commonly used password or a predictable word.',
      },
    ]
  }

  if (lower.includes('repeats') || lower.includes('sequence')) {
    return [
      {
        category: 'repeated-sequence',
        severity: 'medium',
        explanation: 'This password contains a repeating or sequential pattern.',
      },
    ]
  }

  return []
}

/**
 * Checks whether the password embeds an optional user-supplied context term.
 *
 * The term stays in memory only; no finding ever contains it. Returns null when
 * no context was provided so the UI can tell "not checked" from "no match".
 */
export function detectContext(
  password: string,
  context: string | undefined,
): Finding[] | null {
  const term = context?.trim().toLowerCase() ?? ''
  if (term.length === 0) return null

  if (password.toLowerCase().includes(term)) {
    return [
      {
        category: 'personal-context',
        severity: 'high',
        explanation:
          'This password contains the personal term you provided, which attackers can guess.',
      },
    ]
  }

  return []
}

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

function isNumeric(char: string): boolean {
  return char >= '0' && char <= '9'
}

function isAlphabetic(char: string): boolean {
  return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}

/** Longest run where `same` returns true for consecutive characters. */
function longestRun(
  password: string,
  same: (a: string, b: string) => boolean,
): { length: number } {
  let best = 0
  let run = 1

  for (let i = 1; i < password.length; i += 1) {
    if (same(password[i - 1], password[i])) {
      run += 1
      if (run > best) best = run
    } else {
      run = 1
    }
  }

  return { length: best }
}

/**
 * Longest run where consecutive characters map to values that step by +1 or
 * -1. `value` returns null for characters outside the class being tested.
 * Used for digits, alphabet letters, and keyboard-row adjacency.
 */
function longestDirectionalRun(
  password: string,
  value: (char: string) => number | null,
): { length: number } {
  let best = 0
  let ascending = 1
  let descending = 1

  for (let i = 1; i < password.length; i += 1) {
    const prev = value(password[i - 1])
    const curr = value(password[i])

    if (prev === null || curr === null) {
      ascending = 1
      descending = 1
      continue
    }

    const delta = curr - prev
    ascending = delta === 1 ? ascending + 1 : 1
    descending = delta === -1 ? descending + 1 : 1

    best = Math.max(best, ascending, descending)
  }

  return { length: best }
}

/**
 * Length of the longest substring that repeats back-to-back at least twice
 * (e.g. "abcabc" -> 3). Null when nothing repeats.
 */
function longestRepeatedSequence(password: string): number | null {
  let best = 0

  for (let size = 1; size <= Math.floor(password.length / 2); size += 1) {
    for (let start = 0; start + size * 2 <= password.length; start += 1) {
      let matches = true
      for (let offset = 0; offset < size; offset += 1) {
        if (password[start + offset] !== password[start + size + offset]) {
          matches = false
          break
        }
      }
      // Skip uniform runs like "aaaa": those are repeated *characters*, which
      // a separate detector reports with a more accurate explanation.
      if (matches && !isUniform(password, start, size) && size > best) {
        best = size
      }
    }
  }

  return best > 0 ? best : null
}

/** True when password[start..start+size) is one character repeated. */
function isUniform(password: string, start: number, size: number): boolean {
  for (let i = 1; i < size; i += 1) {
    if (password[start + i] !== password[start]) return false
  }
  return true
}
