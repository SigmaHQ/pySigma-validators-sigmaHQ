# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Initial comprehensive validator set for SigmaHQ rules (49 validators)
- Configurable parameters for flexible validation rules
- Taxonomy-based field validation using sigmahq_taxonomy.json

### Changed
- Updated README to reflect current implementation status
- Removed references to non-existent configuration files
- Clarified programmatic usage in documentation

## [v0.20.1] - 2023-12-06
### Fixed
- **Validator improvements**: Enhanced validation logic for title formatting and field name checks
- **Bug fixes**: Resolved issues with status validation and correlation rule detection
- **Performance**: Optimized validation execution for large rule sets

## [v0.20.0] - 2023-11-26
### Added
- **New validators**:
  - `SigmahqFieldUserValidator`: Enhanced User field name localization checks
  - `SigmahqInvalidHashKvValidator`: Improved Sysmon Hash key-value search validation
- **Configuration support**: Added configurable word lists for falsepositive validation

## [v0.12.2] - 2023-11-11
### Fixed
- **Validation accuracy**:
  - Improved detection of redundant modified fields
  - Enhanced status field validation with folder checks
- **Edge cases**: Better handling of empty or malformed rule files

## [v0.12.1] - 2023-10-31
### Security
- **Dependency updates**:
  - Updated sigma dependency to v4.0.0 with security patches
  - Fixed potential vulnerability in regex pattern validation
- **Validation hardening**: Added input sanitization for rule parsing

## [v0.12.0] - 2023-10-31
### Added
- **Correlation rules support**:
  - Enhanced `SigmahqCorrelationRulesMinimumValidator`
  - Improved group-by field validation
- **Metadata validation**: Stronger checks for level and logsource fields

## [v0.11.0] - 2023-10-23
### Changed
- **Breaking changes**:
  - Updated validator naming conventions to be more consistent
  - Modified severity levels for certain validation cases
- **Improvements**:
  - Better error messages and issue descriptions
  - Enhanced test coverage for edge cases

## [v0.10.2] - 2023-09-23
### Fixed
- **Bug fixes**:
  - Resolved false positives in title validation
  - Fixed issues with field existence checks
- **Performance**: Optimized validator execution order

## [v0.10.1] - 2023-09-22
### Documentation
- **Improved documentation**:
  - Enhanced README with detailed configuration table
  - Added validation severity levels explanation
  - Better examples in contributing guidelines

## [v0.10.0] - 2023-07-29
### Added
- **New validators**:
  - `SigmahqTagsTechniquesWithoutTacticsValidator`
  - `SigmahqInvalidAllModifierValidator`
- **Configuration system**: Initial support for configurable parameters

## [v0.9.6] - 2023-05-29
### Fixed
- **Stability improvements**:
  - Better handling of malformed YAML files
  - Improved error recovery during validation
- **Validation accuracy**: Enhanced detection of invalid field names

## [v0.1.0] - Initial Development (YYYY-MM-DD)
### Added
- **Core infrastructure**:
  - Validator base classes and patterns
  - Comprehensive test framework
- **Initial validators**:
  - Author, date, description validation
  - Basic condition and field validation
- **Taxonomy support**: Integrated sigmahq_taxonomy.json for field validation

## Types of changes
```markdown
[Unreleased]
### Added
- A new feature or validator

### Changed
- A breaking change or significant improvement

### Deprecated
- A previously used feature or validator

### Removed
- A feature or validator that was removed

### Fixed
- A bug fix or improvement to existing functionality

### Security
- Vulnerability patches and security-related changes
```

## How to contribute
1. **Check guidelines**: Review [CONTRIBUTING.md](CONTRIBUTING.md)
2. **Discuss changes**: Open an issue for major changes
3. **Submit PRs**: Follow code style and documentation standards
4. **Testing**: Ensure comprehensive test coverage (1:1 with validators)

## Support
For issues or questions, please:
- Check existing GitHub issues before opening new ones
- Contact maintainers via GitHub discussions