# Password Analyzer

A local-first web application that assesses password guessability, identifies
common weaknesses, and recommends stronger alternatives. All analysis runs
in the browser — passwords are never sent to a backend or external API, never
logged to the console, and never stored in browser storage or on disk.

## Tech Stack

- React 19 + TypeScript
- Vite
- Plain CSS (no UI libraries)
- [zxcvbn](https://github.com/dropbox/zxcvbn) for strength estimation
- Vitest + React Testing Library for testing

## Getting Started

Requirements: Node.js 20+ and npm.

```bash
npm install      # install dependencies
npm run dev      # start the dev server (Vite)
npm test         # run the test suite once
npm run test:watch  # run tests in watch mode
npm run build    # typecheck and build for production
npm run preview  # serve the production build locally
npm run typecheck  # TypeScript check only
```

## Project Structure

```
src/
  components/        # Small, reusable UI components
    PasswordInput.tsx  # Password field with show/hide toggle
    Results.tsx        # Score, indicator, grouped weaknesses, recommendations, crack times
  engine/
    analyzePassword.ts   # zxcvbn wrapper returning sanitized results
    patterns.ts          # Repeat/sequence/keyboard/context pattern detectors
    patterns.test.ts
    analyzePassword.test.ts
  styles/
    index.css        # Global stylesheet
  test/
    setup.ts         # Vitest setup (jest-dom matchers)
  App.tsx            # Application shell
  App.test.tsx       # Application tests
  main.tsx           # Entry point
vite.config.ts       # Vite + Vitest configuration
```

## Security Model

- Passwords are processed entirely in memory in the browser.
- No network requests contain password data.
- No console logging of password values.
- No persistence to localStorage, sessionStorage, cookies, or files.
- Passwords are limited to 256 UTF-16 code units. Longer input is rejected
  (never silently truncated) before analysis, so zxcvbn is never run on
  oversized input. This bounds analysis time and prevents a UI freeze.
- Dependencies are kept free of known vulnerabilities: `npm audit` and
  `npm audit --omit=dev` both report 0 vulnerabilities. The test toolchain runs
  on `vitest@4.1.12` (patched); it is dev-only and never ships to production.

## Status

Milestone 2: zxcvbn-backed analysis. Clicking Analyze evaluates the password
client-side and displays a 0-4 score with label, a strength indicator, warnings,
suggestions, and estimated crack times for zxcvbn's modeled attack scenarios.

Milestone 3: advanced weakness detection. A separate `patterns` module adds
structured findings — repeated characters, repeated sequences, numeric and
alphabetic sequences, keyboard runs, common passwords (via zxcvbn feedback),
predictable words, and an optional personal-term check. Each finding carries a
category, an explanation, and a severity (High/Medium/Low), sorted most severe
first and shown in a compact Weaknesses section.

The personal term is optional, used only for in-browser pattern checking, and is
never stored, transmitted, or echoed back in results. All findings are
sanitized: they report lengths and categories, never the matched substring.

Crack times are rough estimates under stated assumptions, not guarantees; a high
score never means a password is absolutely secure. The engine returns a
sanitized result and never retains the original password or the raw zxcvbn
result in state.

Milestone 4: results and usability refinement. Findings are grouped under
"Patterns" and "Common and personal words" subheadings; a clear no-findings
state is shown when nothing is detected. Recommendations are deduplicated and
combine actionable advice for each weakness with zxcvbn's own suggestions. A
Reset button clears inputs and results and returns focus to the password field;
stale results are cleared automatically when either input changes. Disclaimers
state that ratings are estimates, not security guarantees, and that breach
databases are not checked.

Milestone 5: security validation and F-1/F-2 remediation. A full audit
(SECURITY_REVIEW.md) confirmed the local-only privacy model holds. The one
High finding — very long input freezing the tab — is now fixed: the engine
enforces a 256-character maximum before invoking zxcvbn, rejecting oversized
input with a clear message and never truncating silently. The Low finding on
dependencies is also resolved: the test toolchain was upgraded to the patched
`vitest@4.1.12`, which fixes the `@vitest/mocker` advisories and removes the
vulnerable `tinypool` worker pool. Production dependencies were already clean
and remain unchanged.

Not implemented (out of scope): breach checking, password generation,
authentication. zxcvbn's internal `matches` array is not exposed by the bundled
build, so dictionary detection relies on zxcvbn's feedback warnings rather than
raw match data.
