# pySigma_validators_sigmaHQ

![Tests](https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/frack113/b27ee1cbe964fb1a299cc20c3403f8c8/raw/pySigma-validators-sigmaHQ.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)


## 🌟 Purpose

Create all validators specific to the requirements of the SigmaHQ rules repository.

This package provides comprehensive validation for Sigma rules, ensuring they meet SigmaHQ's quality standards and best practices through:

- **Structural validation**: Checks required fields and proper formatting
- **Content validation**: Ensures descriptions, titles, and tags follow conventions
- **Technical validation**: Validates detection logic, field usage, and modifiers
- **Metadata validation**: Verifies status, dates, authorship, and references

## 📦 Installation

Install the package using pip:

```bash
pip install pySigma-validators-sigmaHQ
```

## 🏗️ Validators

### Core Rule Structure
- **Author**:
  - `SigmahqAuthorExistenceValidator`: Ensures author field is present

- **Date & Modification**:
  - `SigmahqDateExistenceValidator`: Validates required date field
  - `SigmahqModifiedDateOrderValidator`: Checks modified date ordering
  - `SigmahqModifiedWithoutDateValidator`: Prevents modified without date
  - `SigmahqRedundantModifiedValidator`: Detects unnecessary modified fields

- **Description**:
  - `SigmahqDescriptionExistenceValidator`: Ensures description exists
  - `SigmahqDescriptionLengthValidator`: Validates minimum description length (configurable)
  - `SigmahqLinkInDescriptionValidator`: Checks for proper hyperlink references

### Detection Logic
- **Condition Validation**:
  - `SigmahqOfthemConditionValidator`: Validates 'of them' usage patterns
  - `SigmahqOfselectionConditionValidator`: Ensures correct 'All/X of' format
  - `SigmahqMissingAsteriskConditionValidator`: Checks for required asterisks

- **Field Validation**:
  - `SigmahqCategoryEventIdValidator`: Validates EventID field usage by category
  - `SigmahqCategoryWindowsProviderNameValidator`: Ensures proper Provider_Name usage
  - `SigmahqUnsupportedRegexGroupConstructValidator`: Detects unsupported regex patterns

### Correlation Rules
- **Correlation Validation**:
  - `SigmahqCorrelationRulesMinimumValidator`: Enforces minimum rule count for correlations
  - `SigmahqCorrelationGroupByExistenceValidator`: Validates required group-by fields

### Filename Conventions
- `SigmahqFilenameConventionValidator`: Ensures proper filename patterns
- `SigmahqCorrelationFilenamePrefixValidator`: Validates correlation filenames start with 'correlation_'
- `SigmahqFilenamePrefixValidator`: Checks for correct prefix usage

### Metadata Fields
- **Level**:
  - `SigmahqLevelExistenceValidator`: Validates required level field

- **Logsource**:
  - `SigmahqLogsourceUnknownValidator`: Detects unknown log sources
  - `SigmahqSysmonMissingEventidValidator`: Ensures Sysmon rules have EventID

- **Status**:
  - `SigmahqStatusExistenceValidator`: Checks for required status field
  - `SigmahqStatusValidator`: Validates Deprecated/Unsupported statuses with folder checks
  - `SigmahqStatusToHighValidator`: Prevents premature status elevation (configurable min_days)

### Tagging System
- **Tag Validation**:
  - `SigmahqTagsUniqueDetectionValidator`: Ensures unique detection tags
  - `SigmahqTagsDetectionValidator`: Validates required detection tags by folder
  - `SigmahqTagsUniqueTlpValidator`: Checks TLP tag uniqueness
  - `SigmahqTagsTlpValidator`: Validates authorized TLP tags (configurable word list)
  - `SigmahqTagsTechniquesWithoutTacticsValidator`: Ensures technique-tactic pairing

### Title Formatting
- **Title Validation**:
  - `SigmahqTitleLengthValidator`: Enforces maximum title length (default: 120 chars, configurable)
  - `SigmahqTitleStartValidator`: Prevents titles starting with 'Detect'/'Detects'
  - `SigmahqTitleEndValidator`: Ensures proper title ending (no trailing dots)
  - `SigmahqTitleCaseValidator`: Validates article/preposition casing

### References & Links
- `SigmahqGithubLinkValidator`: Validates GitHub link presence in rules
- `SigmahqMitreLinkValidator`: Checks for proper MITRE tag usage instead of links

### False Positives
- **Falsepositive Validation**:
  - `SigmahqFalsepositivesCapitalValidator`: Ensures proper capitalization
  - `SigmahqFalsepositivesBannedWordValidator`: Detects banned words (configurable word list)
  - `SigmahqFalsepositivesTypoWordValidator`: Checks for common typos

### Field-Specific Validation (Detection Items)
- **Field Name**:
  - `SigmahqSpaceFieldNameValidator`: Prevents space in field names
  - `SigmahqFieldnameCastValidator`: Detects type casting errors
  - `SigmahqInvalidFieldnameValidator`: Validates field existence in logsource
  - `SigmahqFieldUserValidator`: Checks for localized User field names
  - `SigmahqInvalidHashKvValidator`: Validates Sysmon Hash key-value searches
  - `SigmahqRedundantFieldValidator`: Detects redundant field usage

- **Fields**:
  - `SigmahqFieldsExistenceValidator`: Validates deprecated fields usage
  - `SigmahqUnknownFieldValidator`: Detects unknown field references

- **Modifier**:
  - `SigmahqFieldDuplicateValueValidator`: Checks for duplicate values in field lists
  - `SigmahqInvalidAllModifierValidator`: Prevents invalid All modifier usage

## 🧬 Configuration

### Current Implementation
All validation logic is implemented directly in validator classes within `sigma/validators/sigmahq`.
No external configuration files are currently required.

### Configurable Parameters

| Validator | Parameter | Type | Default Value | Description |
|-----------|----------|------|---------------|-------------|
| Title Length | `max_length` | int | 120 | Maximum allowed title length in characters |
| Status Elevation | `min_days` | int | 60 | Minimum days before status can be elevated beyond EXPERIMENTAL |
| Falsepositive Words | `word_list` | Tuple[str] | See source | List of banned words for falsepositive validation |

### Future Configuration

The architecture supports external configuration through **Class-level parameters** 
For local customizations create a `validator_json` folder in your project root

## 📂 File Structure

```
sigma/
  validators/
    sigmahq/
      [validator_files].py  # All validation logic here (49 validators)
tests/
  sigmahq/                  # Comprehensive test cases (1:1 with validators)
tools/
  sigmahq_taxonomy.json     # Taxonomy data used by field validators
```

## 🛠️ Validation Severity

Validators use the following severity levels:

| Severity | Description | Example Use Cases |
|----------|-------------|-------------------|
| **LOW** | Minor style issues that don't affect functionality | Title casing, redundant fields |
| **MEDIUM** | Potential quality issues that should be addressed | Long titles, missing descriptions |
| **HIGH** | Critical issues that may break rule functionality | Missing required fields, invalid statuses |

All validators currently use MEDIUM severity unless they detect critical issues.

## 📜 Maintainers

This project is maintained by:

* [François Hubaut (@frack113)](https://twitter.com/frack113)
* [Christian Burkard (@phantinuss)](https://twitter.com/phantinuss)


## 🔍 License

GNU Lesser General Public License v2.1 (LGPL-2.1)
See [LICENSE](https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/main/LICENSE) for details.