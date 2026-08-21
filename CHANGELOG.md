# CHANGELOG

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
