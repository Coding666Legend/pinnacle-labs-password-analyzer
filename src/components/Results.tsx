import type { AnalysisResult } from '../engine/analyzePassword'
import { severityLabel, type Finding } from '../engine/patterns'

interface ResultsProps {
  hasAnalyzed: boolean
  analysis: AnalysisResult | null
  error: string | null
}

const SCORE_LEVELS = [0, 1, 2, 3, 4] as const

/** Display groups for findings, in rendering order. */
const FINDING_GROUPS = [
  {
    title: 'Patterns',
    categories: new Set<Finding['category']>([
      'repeated-character',
      'repeated-sequence',
      'numeric-sequence',
      'alphabetic-sequence',
      'keyboard-pattern',
    ]),
  },
  {
    title: 'Common and personal words',
    categories: new Set<Finding['category']>([
      'common-password',
      'predictable-word',
      'personal-context',
    ]),
  },
] as const

function WeaknessItem({ finding }: { finding: Finding }): React.JSX.Element {
  return (
    <li className={`weakness weakness--${finding.severity}`}>
      <span className={`severity severity--${finding.severity}`}>
        {severityLabel(finding.severity)}
      </span>{' '}
      <span>{finding.explanation}</span>
    </li>
  )
}

function Results({ hasAnalyzed, analysis, error }: ResultsProps): React.JSX.Element {
  return (
    <section className="results" aria-live="polite">
      <h2>Results</h2>

      {!hasAnalyzed && (
        <p className="results__placeholder">
          Enter a password and select Analyze to see results.
        </p>
      )}

      {hasAnalyzed && error !== null && (
        <p className="results__error" role="alert">
          {error}
        </p>
      )}

      {hasAnalyzed && error === null && analysis !== null && (
        <div className="results__analysis">
          <p className={`results__label results__label--score-${analysis.score}`}>
            Strength: {analysis.label} ({analysis.score}/4)
          </p>

          <div
            className={`strength strength--score-${analysis.score}`}
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={4}
            aria-valuenow={analysis.score}
            aria-valuetext={analysis.label}
          >
            {SCORE_LEVELS.map((level) => (
              <span
                key={level}
                className={
                  level <= analysis.score
                    ? 'strength__segment strength__segment--filled'
                    : 'strength__segment'
                }
              />
            ))}
          </div>

          {analysis.findings.length > 0 ? (
            <div className="results__block">
              <h3>Weaknesses</h3>
              {FINDING_GROUPS.map((group) => {
                const grouped = analysis.findings.filter((finding) =>
                  group.categories.has(finding.category),
                )
                if (grouped.length === 0) return null
                return (
                  <div key={group.title} className="results__group">
                    <h4 className="results__group-title">{group.title}</h4>
                    <ul className="weaknesses">
                      {grouped.map((finding) => (
                        <WeaknessItem key={finding.category} finding={finding} />
                      ))}
                    </ul>
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="results__none">
              No specific weaknesses detected — no repeated patterns, common
              passwords, or personal terms were found.
            </p>
          )}

          {analysis.warnings.length > 0 && (
            <div className="results__block">
              <h3>Warnings</h3>
              <ul>
                {analysis.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </div>
          )}

          {analysis.recommendations.length > 0 && (
            <div className="results__block">
              <h3>Recommendations</h3>
              <ul>
                {analysis.recommendations.map((recommendation) => (
                  <li key={recommendation}>{recommendation}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="results__block">
            <h3>Estimated time to crack</h3>
            <p className="results__note">
              These are rough estimates based on zxcvbn's modeled attack
              scenarios, not guaranteed cracking times. Real results depend on
              the attacker's hardware, the hashing scheme, and luck.
            </p>
            <dl className="results__times">
              <dt>Online, throttled (100 guesses/hour)</dt>
              <dd>{analysis.crackTimeEstimates.onlineThrottled}</dd>
              <dt>Online, unthrottled (10 guesses/second)</dt>
              <dd>{analysis.crackTimeEstimates.onlineUnthrottled}</dd>
              <dt>Offline, slow hash (10,000 guesses/second)</dt>
              <dd>{analysis.crackTimeEstimates.offlineSlowHashing}</dd>
              <dt>Offline, fast hash (10 billion guesses/second)</dt>
              <dd>{analysis.crackTimeEstimates.offlineFastHashing}</dd>
            </dl>
          </div>

          <p className="results__disclaimer">
            A high score means the password resists the attacks modeled here. It
            is not a guarantee that the password is secure — reuse, phishing, and
            data breaches are not covered by this estimate. This tool does not
            currently check breach databases, so it cannot tell you whether a
            password has already appeared in a known leak.
          </p>
        </div>
      )}
    </section>
  )
}

export default Results
