# Security Review — Password Analyzer

**Milestone 5: Security Validation**
**Scope:** the application itself (a local-first password strength analyzer), not any password it is pointed at.
**Method:** static source review, dynamic input probing, dependency audit, and production-build inspection.
**Date:** current audit run.

---

## 1. Executive summary

The Password Analyzer is a client-side only React application. Passwords and
optional context terms are processed entirely in memory within the browser and
are never transmitted, persisted, or logged. Static review found no network
APIs, no browser-storage APIs, no `dangerouslySetInnerHTML`, and no `eval`-class
calls in application code. The three production dependencies (react, react-dom,
zxcvbn) contain no network or storage primitives.

Both identified issues have been **remediated**; no Critical, High, Medium, or
Low findings remain open:

- **REMEDIATED (was High) — unbounded analysis time (client-side denial of
  service / UI freeze).** zxcvbn's matching cost grows super-linearly with input
  length. A ~2,000 character input previously blocked the main thread for ~79
  seconds. A 256-character cap is now enforced in the engine before zxcvbn runs;
  oversized input is rejected instantly with a clear message and is never
  analyzed. See F-1 for verification.

- **REMEDIATED (was Low) — development-dependency vulnerabilities in the test
  toolchain.** `npm audit` previously reported 3 vulnerabilities (2 critical,
  1 moderate) in `vitest`/`tinypool`/`@vitest/mocker`. The toolchain was upgraded
  to the patched `vitest@4.1.12`, which fixes the `@vitest/mocker` advisories and
  removes `tinypool` entirely. Both `npm audit` and `npm audit --omit=dev` now
  report **0 vulnerabilities**. See F-2 for verification.

No Critical or High findings relate to password leakage, exfiltration, XSS, or
insecure storage. The core privacy model is sound as implemented and verified.

---

## 2. Scope and methodology

**In scope**

- Password and context-term data lifecycle (entry, residence, transform, release).
- Network behavior of application code and production dependencies.
- DOM/XSS surface: HTML insertion and rendering of user-controlled strings.
- Input handling: length, Unicode, emoji, combining characters, control chars.
- Error handling and console output.
- Dependency security (direct and transitive).
- Production configuration: Vite config, env vars, source maps, secrets.
- Privacy: browser storage, URLs, analytics, telemetry.

**Out of scope**

- The security of any specific password evaluated by the tool.
- Backend or network services (none exist).
- Breach-database checking (not implemented, by design).

**Method**

1. Read every application source file, config file, and the package manifest.
2. Static pattern sweep of `src/` for network, storage, HTML-injection, and
   code-execution APIs.
3. Dynamic probing of the analysis engine with XSS-like, Unicode, combining,
   control-character, and long inputs.
4. `npm audit` (full and `--omit=dev`) plus manual review of the runtime tree.
5. Inspect `dist/` for source maps and accidental secrets.

---

## 3. Findings (by severity)

### F-1 — High → REMEDIATED — Unbounded analysis blocks the main thread (local DoS)

**Affected files:** `src/App.tsx` (submit handler), `src/engine/analyzePassword.ts`,
the `zxcvbn` dependency.

**Evidence / reproduction:** measure engine time versus input length:

| Input length | Analysis time |
|------------- |-------------- |
| 100 chars    | ~40 ms       |
| 200 chars    | ~148 ms      |
| 400 chars    | ~830 ms      |
| 800 chars    | ~5.2 s       |
| 1,600 chars  | ~37 s        |
| ~2,000 chars | ~79 s       |

**Impact:** because analysis runs synchronously on the main thread with no
length cap, a long paste freezes the tab. This is a self-inflicted or
socially-engineered local availability problem. It does **not** expose the
password to any third party.

**Remediation (now implemented):** a maximum accepted length of **256 UTF-16
code units** (`MAX_PASSWORD_LENGTH`) is enforced in
`src/engine/analyzePassword.ts`, *before* `zxcvbn` is invoked. Oversized input
throws a typed `PasswordTooLongError` carrying no password data; `src/App.tsx`
catches it and shows a generic, static message and disables the Analyze button.
Input is **rejected, never silently truncated**. Because the cap lives in the
engine, no caller can reach zxcvbn with oversized input.

**Verification (post-remediation measurement):**

| Input length | Behavior                       | Time    |
|------------- |------------------------------ |-------- |
| 256 chars    | analyzed normally              | ~266 ms |
| 257 chars    | rejected (`PasswordTooLongError`) | ~0.0 ms |
| 2,000 chars  | rejected (`PasswordTooLongError`) | ~0.0 ms |

The F-1 scenario (2,000 chars) now completes in ~0 ms instead of ~79 s.
Tests assert zxcvbn is never invoked for oversized input, and that the
validation message contains no password data.

### F-2 — Low → REMEDIATED — Vulnerabilities in development-only dependencies

**Affected:** `vitest`, `tinypool`, `@vitest/mocker` (devDependencies).

**Evidence (before):** `npm audit` → 3 vulnerabilities (2 critical, 1 moderate):
`tinypool` prototype-pollution/RCE advisories and `@vitest/mocker`
path-traversal / code-injection advisories. `npm audit --omit=dev` →
**0 vulnerabilities** (production was already clean).

**Impact:** none on end users. These packages run only during `npm test` and are
not included in the production bundle. They would matter only in a CI
environment where untrusted test input is processed.

**Remediation (now implemented):** upgraded `vitest` `^3.1.3` → `4.1.12`
(pinned). This is the patched V4 line — the smallest safe change, rather than
the breaking V5 jump npm's `audit fix --force` would have forced. The upgrade:

- brings `@vitest/mocker` from `3.2.7` to `4.1.12` (fixes GHSA-82fw-gwwq-j7x9
  and GHSA-qxg6-89mg-rqv8), and
- removes `tinypool` entirely (fixes GHSA-5gmw-xhrv-c9v3 and GHSA-85c8-ppgw-ccpr)
  — Vitest v4 replaced the worker pool with `tinyexec`/`tinybench`, so the
  vulnerable prototype-pollution gadget is no longer in the tree.

**Verification (after):** `npm audit` → **0 vulnerabilities**;
`npm audit --omit=dev` → **0 vulnerabilities**. All 89 tests pass on v4 with no
changes to any test file; the production bundle is byte-identical to before
(`index-C7cdPEWn.js`, 1,055.57 kB), confirming no effect on shipped output.

Compatibility: `vitest@4.1.12` peer-requires `vite ^6.0.0 || ^7.0.0 ||
^8.0.0` (installed 6.4.5 ✓) and Node `^20 || ^22 || >=24` (installed 24.15.0 ✓).
No breaking-change adaptations to `vite.config.ts`, the tests, or the app were
needed.

### F-3 — Informational → RESOLVED — No input length limit enables F-1

Closed by the same control that remediates F-1: `MAX_PASSWORD_LENGTH = 256`
now exists in `src/engine/analyzePassword.ts` and is enforced before analysis.

### F-4 — Informational — Large bundle from embedded frequency dictionaries

The production bundle is ~1.05 MB (~466 KB gzipped), dominated by zxcvbn's
built-in dictionaries. This is an availability/performance note (slower initial
load on slow links) with no security impact. Source of the size is inherent to
zxcvbn's offline dictionary approach, which is also what keeps the tool
local-first (no server lookups).

---

## 4. Evidence and affected files

- **Password residence:** `src/App.tsx` holds `password` and `context` in
  `useState` only. `analyzePassword()` returns a sanitized object; the raw
  zxcvbn result (which embeds the password) is never stored in state.
- **Stale values:** editing either field clears results via `clearResults()`;
  `Reset` clears both fields and results.
- **No persistence:** `src/` contains zero references to `localStorage`,
  `sessionStorage`, `document.cookie`, `indexedDB`, or `sendBeacon`.
- **No network:** `src/` contains zero references to `fetch`, `XMLHttpRequest`,
  `WebSocket`, or `axios`. Runtime dependency scan of `zxcvbn/dist` and
  `react-dom/cjs` found no `XMLHttpRequest`/`WebSocket`/`sendBeacon`.
- **No HTML injection:** zero `dangerouslySetInnerHTML` / `innerHTML` / `eval` /
  `new Function` in `src/`. React renders all findings as text nodes.
- **No console logging:** zero `console.*` calls in `src/`.
- **Build output:** `dist/` has no `.map` files and no `sourceMappingURL`
  references. No `.env` files exist; `dist` and `dist-ssr` are gitignored.

---

## 5. Reproduction steps

- **F-1 (original):** call `analyzePassword('a1!'.repeat(N))` for increasing N
  and observe time grow super-linearly (~40 ms at N≈100 → ~79 s at ~2,000 chars).
- **F-1 (post-remediation):** `analyzePassword('a1!'.repeat(700))` throws
  `PasswordTooLongError` in ~0 ms without invoking zxcvbn; a 256-char input
  still analyzes normally.
- **F-2 (post-remediation):** run `npm audit` and `npm audit --omit=dev` —
  both now report **0 vulnerabilities** (previously 3 dev-only issues). Confirm
  `tinypool` is absent from `npm ls` and the lockfile.
- **F-2 (original, for reference):** `npm audit` reported 3 issues (2 critical,
  1 moderate) then `npm audit --omit=dev` reported 0 issues.
- **XSS strings:** analyzing `<img src=x onerror=alert(1)>` and
  `<script>alert("xss")</script>` produces ordinary scores/feedback; the
  strings are rendered as text and never inserted as HTML.
- **Context with HTML:** analyzing with context `<b>name</b>` yields a
  `personal-context` finding whose serialized output does not contain `<b>`.

---

## 6. Recommended remediation

1. ~~**Cap input length** before analysis (closes F-1/F-3).~~ **DONE** — 256-char
   cap enforced in the engine before zxcvbn; oversized input rejected with a
   clear message and never analyzed.
2. Optionally run analysis in a **Web Worker** to keep the UI responsive (not
   required now that the cap bounds worst-case cost; not implemented).
3. ~~**Upgrade the test toolchain** (F-2) to a patched vitest major after a
   compatibility check; avoid `--force`.~~ **DONE** — `vitest` `^3.1.3` →
   `4.1.12` (patched V4, smaller than the breaking V5 `--force` would install);
   `@vitest/mocker` → `4.1.12`; `tinypool` removed. Both audits now clean.

---

## 7. Verified security controls

- Analysis is fully client-side; no backend and no outbound requests.
- Passwords and context terms never leave React `useState`; no storage, cookies,
  or URLs.
- No password or context value is written to the console.
- Raw zxcvbn result (containing the password) is never retained in state.
- All findings, recommendations, and errors render as text; no HTML injection
  path exists.
- Error handling is generic and does not echo exception details or input.
- Oversized input is rejected before analysis with a static message that
  contains no password data; passwords are never silently truncated.
- Production bundle contains no source maps and no secrets.
- Dev-only test toolchain is patched (`vitest@4.1.12`); both `npm audit` and
  `npm audit --omit=dev` report 0 vulnerabilities.

---

## 8. Known limitations

- **Input length is capped at 256 UTF-16 code units.** Passwords longer than
  256 code units are rejected rather than analyzed. This is a deliberate,
  documented availability control: it bounds zxcvbn's super-linear cost but
  means the tool will not score very long passphrases. Counting is in UTF-16
  code units, so a surrogate-pair emoji counts as two.
- **F-2 is resolved:** dev toolchain upgraded to `vitest@4.1.12`; no known
  vulnerabilities remain in either runtime or development dependencies (see
  dependency audit below).
- **Dictionary detection** relies on zxcvbn feedback warnings because the
  bundled build does not expose its `matches` array.
- **Keyboard-run detection** is same-row only; diagonal patterns (e.g. `1qaz`)
  are not detected (a detection-quality note, not a security issue).
- The audit used dynamic probing in Node, not a full browser DOM sandbox;
  XSS conclusions rest on React's text-node rendering plus the absence of any
  HTML-injection API in source.

---

## 9. Dependency audit results

**Runtime (shipped) dependencies — clean**

- `react@19.3.1`, `react-dom@19.3.1`, `zxcvbn@4.4.2`
- `npm audit --omit=dev` → **0 vulnerabilities**
- No network or storage primitives found in `zxcvbn/dist` or `react-dom/cjs`.

**Development dependencies — clean (remediated)**

- Before: `vitest@3.2.7` → `@vitest/mocker@3.2.7` (vulnerable, ≤4.1.11) and
  `tinypool@1.1.1` (vulnerable, ≤2.1.1) → 3 advisories (2 critical, 1 moderate).
- After: `vitest@4.1.12`, `@vitest/mocker@4.1.12`; `tinypool` removed from the
  tree (Vitest v4 uses `tinyexec`/`tinybench` instead of the worker pool).
- Advisories resolved:
  - GHSA-5gmw-xhrv-c9v3 — tinypool prototype pollution → RCE (critical)
  - GHSA-85c8-ppgw-ccpr — tinypool prototype pollution → RCE (critical)
  - GHSA-82fw-gwwq-j7x9 — @vitest/mocker path traversal / arbitrary file read
  - GHSA-qxg6-89mg-rqv8 — @vitest/mocker code injection via manual mock
    registration
- `npm audit` → **0 vulnerabilities**; `npm audit --omit=dev` → **0 vulnerabilities**.
- Compatibility verified: vitest 4.1.12 peer-requires vite ^6/^7/^8 (6.4.5 ✓)
  and Node ^20/^22/>=24 (24.15.0 ✓). All 89 tests pass unchanged; production
  bundle byte-identical to pre-upgrade.

---

## Unresolved risks

- ~~**F-1 (High):** client-side freeze on very long input — no length cap in place.~~
  **CLOSED** — 256-char cap enforced in the engine; oversized input rejected in
  ~0 ms without invoking zxcvbn.
- ~~**F-2 (Low):** vulnerable dev-only test toolchain pending a manual upgrade.~~
  **CLOSED** — `vitest` upgraded to `4.1.12`; `@vitest/mocker` patched and
  `tinypool` removed. Both `npm audit` and `npm audit --omit=dev` report 0
  vulnerabilities.
