# pySigma_validators_sigmaHQ

![Tests](https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/frack113/b27ee1cbe964fb1a299cc20c3403f8c8/raw/pySigma-validators-sigmaHQ.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

## 🌟 Purpose

Create all validators specific to the requirements of the SigmaHQ rules repository.

This package provides comprehensive validation for Sigma rules, ensuring they meet SigmaHQ's quality standards and best practices.

## 🏗️ Validators

### Core Rule Structure
- **Author**: Ensures proper author information
  - `SigmahqAuthorExistenceValidator`: Checks if a rule is missing the author field

- **Date & Modification**:
  - `SigmahqDateExistenceValidator`: Checks if a rule is missing the date field
  - `SigmahqModifiedDateOrderValidator`: Validates modified date ordering
  - `SigmahqModifiedWithoutDateValidator`: Ensures modified field exists with date
  - `SigmahqRedundantModifiedValidator`: Detects redundant modified fields

- **Description**:
  - `SigmahqDescriptionExistenceValidator`: Checks for missing descriptions
  - `SigmahqDescriptionLengthValidator`: Validates description length
  - `SigmahqLinkInDescriptionValidator`: Ensures proper hyperlink references

### Detection Logic
- **Condition Validation**:
  - `SigmahqOfthemConditionValidator`: Validates 'of them' usage
  - `SigmahqOfselectionConditionValidator`: Checks 'All/X of' format
  - `SigmahqMissingAsteriskConditionValidator`: Ensures proper asterisk usage

- **Field Validation**:
  - `SigmahqCategoryEventIdValidator`: Validates EventID field usage
  - `SigmahqCategoryWindowsProviderNameValidator`: Checks Provider_Name usage
  - `SigmahqUnsupportedRegexGroupConstructValidator`: Detects unsupported regex patterns

### Correlation Rules
- **Correlation Validation**:
  - `SigmahqCorrelationRulesMinimumValidator`: Ensures minimum correlation rules
  - `SigmahqCorrelationGroupByExistenceValidator`: Validates group-by fields

### Filename Conventions
- `SigmahqFilenameConventionValidator`: Checks filename conventions
- `SigmahqCorrelationFilenamePrefixValidator`: Validates correlation filenames
- `SigmahqFilenamePrefixValidator`: Ensures proper prefix usage

### Metadata Fields
- **Level**:
  - `SigmahqLevelExistenceValidator`: Checks level field existence

- **Logsource**:
  - `SigmahqLogsourceUnknownValidator`: Detects unknown log sources
  - `SigmahqSysmonMissingEventidValidator`: Validates Sysmon EventID usage

- **Status**:
  - `SigmahqStatusExistenceValidator`: Checks status field existence
  - `SigmahqStatusValidator`: Validates Deprecated/Unsupported statuses
  - `SigmahqStatusToHighValidator`: Ensures proper status for new rules

### Tagging System
- **Tag Validation**:
  - `SigmahqTagsUniqueDetectionValidator`: Ensures unique detection tags
  - `SigmahqTagsDetectionValidator`: Validates detection tag presence
  - `SigmahqTagsUniqueTlpValidator`: Checks TLP tag uniqueness
  - `SigmahqTagsTlpValidator`: Validates authorized TLP tags
  - `SigmahqTagsTechniquesWithoutTacticsValidator`: Ensures technique-tactic pairing

### Title Formatting
- **Title Validation**:
  - `SigmahqTitleLengthValidator`: Checks title length
  - `SigmahqTitleStartValidator`: Validates title starting words
  - `SigmahqTitleEndValidator`: Ensures proper title ending
  - `SigmahqTitleCaseValidator`: Validates article/preposition casing

### References & Links
- `SigmahqGithubLinkValidator`: Validates GitHub link presence
- `SigmahqMitreLinkValidator`: Checks MITRE link usage

### False Positives
- **Falsepositive Validation**:
  - `SigmahqFalsepositivesCapitalValidator`: Validates capitalization
  - `SigmahqFalsepositivesBannedWordValidator`: Detects banned words
  - `SigmahqFalsepositivesTypoWordValidator`: Checks for common typos

### Field-Specific Validation (Detection Items)
- **Field Name**:
  - `SigmahqSpaceFieldNameValidator`: Validates field name format
  - `SigmahqFieldnameCastValidator`: Checks for cast errors
  - `SigmahqInvalidFieldnameValidator`: Detects invalid field names
  - `SigmahqFieldUserValidator`: Validates User field usage
  - `SigmahqInvalidHashKvValidator`: Checks hash key-value searches
  - `SigmahqRedundantFieldValidator`: Detects redundant fields

- **Fields**:
  - `SigmahqFieldsExistenceValidator`: Validates deprecated fields
  - `SigmahqUnknownFieldValidator`: Detects unknown fields

- **Modifier**:
  - `SigmahqFieldDuplicateValueValidator`: Checks for duplicate values
  - `SigmahqInvalidAllModifierValidator`: Validates All modifier usage

## 🧬 Configuration

### Current Implementation
All validation logic is implemented directly in the validator classes within the `sigma/validators/sigmahq` directory. No external configuration files are currently required.

### Validator Parameters
Some validators accept configurable parameters through dataclass attributes:
- **Configurable Validators** (using `@dataclass(frozen=True)`):
  - `SigmahqTitleLengthValidator`: `max_length` parameter
  - `SigmahqStatusToHighValidator`: `min_days` parameter
  - `SigmahqFalsepositivesBannedWordValidator`: Word lists for validation

### Future Configuration Options
The architecture supports future configuration through:
1. **Class-level parameters** (as shown above)
2. **External JSON configurations**

For local customizations, you can:
- Create a `validator_json` folder in your project root
- Add JSON files with override parameters for specific validators

## 📂 File Structure
```
sigma/
  validators/
    sigmahq/
      [validator_files].py  # All validation logic here
tests/
  sigmahq/                  # Test cases for each validator
tools/
  sigmahq_taxonomy.json     # Taxonomy data used by some validators
```

## 📜 Maintainer

This pipeline is currently maintained by:

* [François Hubaut (@frack113)](https://twitter.com/frack113)
* [Christian Burkard (@phantinuss)](https://twitter.com/phantinuss)
