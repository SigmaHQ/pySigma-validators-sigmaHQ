# pySigma_validators_sigmaHQ

![Tests](https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/frack113/b27ee1cbe964fb1a299cc20c3403f8c8/raw/pySigma-validators-sigmaHQ.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

## 🌟 Purpose

Create all validators specific to the requirements of the SigmaHQ rules repository

## 🏗️ Validators

This package contains a comprehensive set of validators for Sigma rules that enforce SigmaHQ standards and best practices:

### Title Validators
- `SigmahqTitleLengthValidator` - Checks if rule title exceeds maximum length (120 characters)
- `SigmahqTitleStartValidator` - Ensures rule title doesn't start with "Detect" or "Detects"
- `SigmahqTitleEndValidator` - Verifies rule title doesn't end with a period
- `SigmahqTitleCaseValidator` - Validates proper casing in rule titles

### Metadata Validators
- `SigmahqStatusExistenceValidator` - Checks for required status field
- `SigmahqStatusValidator` - Ensures deprecated/unsupported rules are properly categorized
- `SigmahqDateExistenceValidator` - Verifies date field is present
- `SigmahqDescriptionExistenceValidator` - Ensures description field exists
- `SigmahqDescriptionLengthValidator` - Checks for sufficiently detailed descriptions (minimum 16 characters)
- `SigmahqLevelExistenceValidator` - Validates level field presence
- `SigmahqFalsepositivesCapitalValidator` - Verifies false positive entries start with capital letters
- `SigmahqFalsepositivesBannedWordValidator` - Checks for banned words in false positives ("none", "pentest", "penetration")
- `SigmahqFalsepositivesTypoWordValidator` - Detects common typos in false positive entries
- `SigmahqLinkInDescriptionValidator` - Ensures hyperlinks are placed in references, not descriptions
- `SigmahqUnknownFieldValidator` - Identifies unknown fields used in rules
- `SigmahqRedundantModifiedValidator` - Detects redundant modified field when date equals modified
- `SigmahqStatusToHighValidator` - Verifies new rules don't have overly high status levels for their age
- `SigmahqGithubLinkValidator` - Checks for branch links instead of permalink URLs in GitHub references
- `SigmahqMitreLinkValidator` - Identifies MITRE links that should be tags

### Field Validators
- `SigmahqSpaceFieldNameValidator` - Detects field names with spaces instead of underscores
- `SigmahqFieldnameCastValidator` - Checks for case-sensitive field name mismatches
- `SigmahqInvalidFieldnameValidator` - Validates fields against logsource-specific allowed fields
- `SigmahqFieldDuplicateValueValidator` - Identifies duplicate values in field lists
- `SigmahqInvalidAllModifierValidator` - Ensures "all" modifier is used with multiple values
- `SigmahqFieldUserValidator` - Checks for localized names in user fields
- `SigmahqInvalidHashKvValidator` - Validates Sysmon Hash Key-Value searches follow proper format
- `SigmahqRedundantFieldValidator` - Detects redundant field usage based on logsource

### Log Source Validators
- `SigmahqLogsourceUnknownValidator` - Identifies rules using unknown log sources
- `SigmahqSysmonMissingEventidValidator` - Ensures sysmon service rules include EventID field

### Filename Validators
- `SigmahqFilenameConventionValidator` - Validates rule filenames match SigmaHQ convention (10-90 characters, lowercase, underscore-separated)
- `SigmahqFilenamePrefixValidator` - Checks that rule filename prefixes match expected log source patterns

### Detection Validators
- `SigmahqCategoryEventIdValidator` - Ensures EventID field isn't used with inappropriate windows categories
- `SigmahqCategoryWindowsProviderNameValidator` - Validates Provider_Name usage for appropriate windows categories
- `SigmahqUnsupportedRegexGroupConstructValidator` - Detects unsupported regex group constructs like lookahead/lookbehind

## 🧬 Data

All the data value are in the config.py

To use a local json version, you need to put them in a `validator_json` folder visible from the launch directory.

## 📜 Maintainer

This pipeline is currently maintained by:

* [François Hubaut (@frack113)](https://twitter.com/frack113)
* [Christian Burkard (@phantinuss)](https://twitter.com/phantinuss)
