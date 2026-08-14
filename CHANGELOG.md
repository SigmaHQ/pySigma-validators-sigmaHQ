# CHANGELOG

## 2026-08-14 - v0.21.1

### New Validators
- `sigmahq_trademark` — Titles must not contain trademarked terms
- `sigmahq_source_eventlog` — EventLog products must specify source/eventlog
- `sigmahq_license` — metadata.license must be a known SPDX identifier
- `sigmahq_event_id_process_creation` — EventID 1/4688 requires process_creation category
- `sigmahq_selection_single_value` — Single-item lists must be on one line
- `sigmahq_selection_alphabetical_order` — Multi-item lists must be sorted alphabetically

### Docs
- README updated with complete validator list (55 validators)

### Maintenance
- Bump check-jsonschema from 0.29.4 to 0.30.0 (CVE-2024-53848 fix)

## 2024-08-09

- Update taxonomy
- Use json for data instead of config.py
- Use diskcache for caching remote data
- Fix invalid sigma syntax
- Move field validators to validator files
