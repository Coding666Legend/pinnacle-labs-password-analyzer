import zxcvbn from 'zxcvbn'
import {
  detectContext,
  detectKeyboardPatterns,
  detectRepeats,
  detectSequences,
  findingsFromFeedback,
  type Finding,
} from './patterns'

/**
 * Password analysis engine.
 *
 * Wraps zxcvbn and returns a small, sanitized result that is safe to keep in
 * React state. The raw zxcvbn result object contains the original password,
 * so it must never be stored — only the fields extracted here.
 */

export type StrengthScore = 0 | 1 | 2 | 3 | 4

export type StrengthLabel =
  | 'Very Weak'
  | 'Weak'
  | 'Fair'
  | 'Strong'
  | 'Very Strong'

/** Human-readable estimates for zxcvbn's modeled attack scenarios. */
export interface CrackTimeEstimates {
  /** Attacker limited to ~100 guesses per hour (e.g. an online login form). */
  onlineThrottled: string
  /** Attacker making ~10 unthrottled guesses per second. */
  onlineUnthrottled: string
  /** Offline attack against a slow hash, ~10,000 guesses per second. */
  offlineSlowHashing: string
  /** Offline attack against a fast hash, ~10 billion guesses per second. */
  offlineFastHashing: string
}

/** Sanitized analysis result. Contains no password data. */
export interface AnalysisResult {
  score: StrengthScore
  label: StrengthLabel
  warnings: string[]
  /** Raw zxcvbn suggestions, deduplicated. Kept for compatibility. */
  suggestions: string[]
  /** Actionable, deduplicated recommendations for the detected weaknesses. */
  recommendations: string[]
  crackTimeEstimates: CrackTimeEstimates
  /** Structured weakness findings, most severe first. */
  findings: Finding[]
}

const SCORE_LABELS: Readonly<Record<StrengthScore, StrengthLabel>> = {
  0: 'Very Weak',
  1: 'Weak',
  2: 'Fair',
  3: 'Strong',
  4: 'Very Strong',
}

/**
 * Maximum password length we will analyze, in UTF-16 code units.
 *
 * zxcvbn's matching cost grows super-linearly with input length, so an
 * unbounded input can block the main thread (see SECURITY_REVIEW.md, F-1).
 * Measured: ~2,000 characters took ~79 seconds. Real-world passwords are far
 * shorter, so 256 is a generous cap that bounds worst-case cost.
 */
export const MAX_PASSWORD_LENGTH = 256

/**
 * Raised when the password exceeds {@link MAX_PASSWORD_LENGTH}.
 *
 * This is a deliberate validation signal so callers can show a friendly
 * message. The error carries no password data.
 */
export class PasswordTooLongError extends Error {
  readonly maxLength = MAX_PASSWORD_LENGTH

  constructor(maxLength: number = MAX_PASSWORD_LENGTH) {
    // Static message: never interpolate the password or its length-derived data.
    super(`Password exceeds the maximum analysable length of ${maxLength} characters.`)
    this.name = 'PasswordTooLongError'
  }
}

/**
 * zxcvbn's display values are always strings at runtime, but the type
 * declarations allow numbers, so normalize defensively.
 */
function toDisplayString(value: string | number): string {
  return typeof value === 'number' ? String(value) : value
}

/** Maps a numeric zxcvbn score (0-4) to its display label. */
export function mapStrengthLabel(score: number): StrengthLabel {
  if (!Number.isInteger(score) || score < 0 || score > 4) {
    throw new RangeError(`Score must be an integer between 0 and 4, received ${score}`)
  }
  return SCORE_LABELS[score as StrengthScore]
}

/** Relative ordering used to sort findings most-severe first. */
const SEVERITY_RANK: Readonly<Record<Finding['severity'], number>> = {
  high: 0,
  medium: 1,
  low: 2,
}

/** Removes duplicate strings while preserving first-seen order. */
function dedupe(values: string[]): string[] {
  return [...new Set(values)]
}

/**
 * Actionable recommendation for each detected weakness category.
 *
 * Only categories with a concrete fix are listed; wording never includes the
 * password, a matched substring, or the context term.
 */
const RECOMMENDATION_BY_CATEGORY: Readonly<Partial<Record<Finding['category'], string>>> = {
  'repeated-character':
    'Replace long runs of a single character with unrelated characters.',
  'repeated-sequence':
    'Avoid repeating the same short sequence; build one longer random pattern instead.',
  'numeric-sequence':
    'Break up ascending or descending digit runs with unrelated digits.',
  'alphabetic-sequence':
    'Avoid consecutive alphabet stretches such as "abcd"; mix the order.',
  'keyboard-pattern':
    'Avoid straight keyboard rows; combine characters from different rows.',
  'common-password':
    'Pick a password that is not based on a commonly used one.',
  'predictable-word':
    'Replace predictable or dictionary words with less common ones.',
  'personal-context':
    'Remove personal terms such as names or pet names from the password.',
}

/**
 * Builds a concise, deduplicated recommendation list from the findings and
 * zxcvbn's own suggestions.
 */
function buildRecommendations(
  findings: Finding[],
  zxcvbnSuggestions: string[],
): string[] {
  const fromFindings = findings.flatMap((finding) => {
    const recommendation = RECOMMENDATION_BY_CATEGORY[finding.category]
    return recommendation === undefined ? [] : [recommendation]
  })

  return dedupe([...fromFindings, ...zxcvbnSuggestions])
}

/** Options that alter analysis without changing the core zxcvbn scoring. */
export interface AnalyzeOptions {
  /** Optional personal term to check for. Kept in memory only. */
  context?: string
}

/**
 * Collects, deduplicates, and sorts weakness findings.
 *
 * Findings are compared by category only — explanations for the same category
 * are identical, so this cannot discard distinct information.
 */
function collectFindings(password: string, warning: string, context?: string): Finding[] {
  const all = [
    ...detectRepeats(password),
    ...detectSequences(password),
    ...detectKeyboardPatterns(password),
    ...findingsFromFeedback(warning),
    ...(detectContext(password, context) ?? []),
  ]

  const seen = new Set<Finding['category']>()
  const deduped = all.filter((finding) => {
    if (seen.has(finding.category)) return false
    seen.add(finding.category)
    return true
  })

  return deduped.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
}

/**
 * Analyzes a password entirely in memory.
 *
 * Returns `null` for empty input. Throws {@link PasswordTooLongError} when the
 * password exceeds {@link MAX_PASSWORD_LENGTH} — in that case zxcvbn is never
 * invoked. The returned object contains only sanitized display fields — never
 * the original password or the raw zxcvbn result.
 */
export function analyzePassword(
  password: string,
  options: AnalyzeOptions = {},
): AnalysisResult | null {
  if (password.length === 0) {
    return null
  }

  // Enforce the length cap before any expensive work. This is the security
  // boundary that prevents a main-thread denial of service (F-1). The password
  // is neither truncated nor logged — oversized input is rejected outright.
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new PasswordTooLongError()
  }

  const result = zxcvbn(password)
  const display = result.crack_times_display
  // Validate the score so a malformed zxcvbn result cannot reach state.
  const label = mapStrengthLabel(result.score)
  const warning = result.feedback.warning ?? ''
  const suggestions = dedupe([...result.feedback.suggestions])
  const findings = collectFindings(password, warning, options.context)

  return {
    score: result.score as StrengthScore,
    label,
    warnings: warning ? [warning] : [],
    suggestions,
    recommendations: buildRecommendations(findings, suggestions),
    crackTimeEstimates: {
      onlineThrottled: toDisplayString(display.online_throttling_100_per_hour),
      onlineUnthrottled: toDisplayString(display.online_no_throttling_10_per_second),
      offlineSlowHashing: toDisplayString(display.offline_slow_hashing_1e4_per_second),
      offlineFastHashing: toDisplayString(display.offline_fast_hashing_1e10_per_second),
    },
    findings,
  }
}
