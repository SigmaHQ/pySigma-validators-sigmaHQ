# CHANGELOG

## 2026-11-08 - v0.30.1

- Add `SigmahqReferencesAlphabeticalOrderValidator` in
  `sigma/validators/sigmahq/references.py` to check that `references` are sorted
  alphabetically (case-insensitive)
- Add `SigmahqTagsAlphabeticalOrderValidator` in
  `sigma/validators/sigmahq/tags.py` to check that `tags` are sorted by
  namespace, then name (case-insensitive, two-level alphabetical order)

## 2026-11-07 - v0.30.0

- **Breaking:** require pySigma 2.x (`pysigma >=2.0.0,<3.0.0`)
- **Breaking:** drop Python 3.10 support; require `>=3.11,<4.0` (matches pySigma 2.x)
- Replace the `diskcache` dependency with `diskcache-community`, imported as
  `diskcache_community`, as required by pySigma 2.x
- Test the unsupported-regex-group-construct validator with `TrustedPolicy`
  (Python regex engine) so lookahead/lookbehind rules stay parseable under the
  default RE2 policy
- Tooling: target Python 3.11 for ruff and mypy; remove 3.10 from the CI matrix
- Add UUID v4 identifier validators
- Add file event and PowerShell file name data
- Add missing taxonomy log sources and the ADFS Windows logsource
- Add a security policy with private vulnerability reporting

## 2026-08-21 - v0.21.1

- Harden data loading: warn on http:// URLs, validate local file paths
- Remove mutable state from detection item validators
- Performance: single-pass technique/tactic check, hoisted constants
- Lint: replace magic-value noqas with named constants

## 2024-08-09

- Update taxonomy
- Use json for data instead of config.py
- Use diskcache for caching remote data
- Fix invalid sigma syntax
- Move field validators to validator files
