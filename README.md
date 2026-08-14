# pySigma_validators_sigmaHQ

![Tests](https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/frack113/b27ee1cbe964fb1a299cc20c3403f8c8/raw/pySigma-validators-sigmaHQ.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

## 🌟 Purpose

Create all validators specific to the requirements of the SigmaHQ rules repository

## 🏗️ Validators

| Validator | Description |
|---|---|
| `sigmahq_author_existence` | Checks if a rule is missing the author field. |
| `sigmahq_category_event_id` | Checks if a rule uses an EventID field with a windows category logsource that doesn't require it. |
| `sigmahq_category_windows_provider_name` | Checks if a rule uses a Provider_Name field with a windows category logsource that doesn't require it. |
| `sigmahq_correlation_filename_prefix` | Check that correlation rule filenames start with 'correlation_'. |
| `sigmahq_correlation_group_by_existence` | Checks if a correlation rule has a group-by field for types that require it. |
| `sigmahq_correlation_rules_minimum` | Checks if temporal correlation rules have at least 2 rules. |
| `sigmahq_date_existence` | Checks if a rule is missing the date field. |
| `sigmahq_description_existence` | Checks if a rule is missing the description field. |
| `sigmahq_description_length` | Checks if a rule has an overly brief description. |
| `sigmahq_event_id_process_creation` | Checks if a rule uses EventID 1 or 4688 with Provider_Name instead of process_creation category. |
| `sigmahq_falsepositives_banned_word` | Checks if a rule contains a falsepositive entry that is part of the banned word list. |
| `sigmahq_falsepositives_capital` | Checks if a rule falsepositive entry starts with a capital letter. |
| `sigmahq_falsepositives_typo_word` | Checks if a rule falsepositive entry contains a common typo. |
| `sigmahq_field_duplicate_value` | Check unique values in field lists. |
| `sigmahq_field_user` | Check a User field use a localized name. |
| `sigmahq_fieldname_cast` | Check field name have a cast error. |
| `sigmahq_fields_existence` | Checks if a rule is using the deprecated field fields. |
| `sigmahq_filename_convention` | Check a rule filename against SigmaHQ filename convention. |
| `sigmahq_filename_prefix` | Check a rule filename against SigmaHQ filename prefix convention. |
| `sigmahq_github_link` | Checks if a rule has a branch GitHub link. |
| `sigmahq_invalid_all_modifier` | Check All modifier used with a single value. |
| `sigmahq_invalid_fieldname` | Check field name do not exist in the logsource. |
| `sigmahq_invalid_hash_kv` | Check field Sysmon Hash Key-Value search is valid. |
| `sigmahq_level_existence` | Checks if a rule is missing the level field. |
| `sigmahq_license` | Checks if a rule has a malformed 'license' field. |
| `sigmahq_link_in_description` | Checks if a rule has a description field that contains a reference to a hyperlink. |
| `sigmahq_logsource_unknown` | Checks if a rule uses an unknown logsource. This validator verifies that all logsource keys (product_category_service) are registered in the data taxonomy. If not, it raises a HIGH severity validation issue. |
| `sigmahq_missing_asterisk_condition` | Check the use of the '1/all of ' keyword without an asterisk in the condition. |
| `sigmahq_mitre_link` | Checks if a rule uses a MITRE link instead of tag. |
| `sigmahq_modified_date_order` | Checks if a rule has a modified field that has value older than the date field. |
| `sigmahq_modified_without_date` | Checks if a rule has a modified field without a date field. |
| `sigmahq_ofselection_condition` | Check use of the 'All/X of ' format with only one selection in the detection section. |
| `sigmahq_ofthem_condition` | Check use of the ' of them' keyword with only a single selection in the detection section. |
| `sigmahq_redundant_field` | Check if a field name is already covered by the logsource. |
| `sigmahq_redundant_modified` | Checks if a rule has a redundant modified field. |
| `sigmahq_selection_single_value` | Checks if any selection has a list with only 1 element. |
| `sigmahq_source_eventlog` | Checks if a detection contains 'Source: Eventlog' which is redundant. |
| `sigmahq_space_field_name` | Check if rules uses a field name that contains a space instead of an underscore. |
| `sigmahq_status` | Checks if a rule uses a status field with the value Deprecated or Unsupported, and its not located in the appropriate folder. |
| `sigmahq_status_existence` | Checks if a rule is missing the status field. |
| `sigmahq_status_to_high` | Checks if a new rule has a valid status regarding its age. |
| `sigmahq_sysmon_missing_eventid` | Checks if a rule using Sysmon logsource is missing the EventID field. This validator ensures that all rules using Windows Sysmon logsource have at least one detection item with the EventID field, which is required for proper event filtering. |
| `sigmahq_tags_detection` | Checks if a rule in a specific folder has the corresponding detection tag. |
| `sigmahq_tags_techniques_without_tactics` | Ensures that MITRE ATT&CK technique tags have their corresponding tactic tags. |
| `sigmahq_tags_tlp` | Checks if a rule uses a non-authorized TLP tag. |
| `sigmahq_tags_unique_detection` | Ensures that the tag.namespace 'detection' is unique in the tags. |
| `sigmahq_tags_unique_tlp` | Ensures that the tag.namespace 'tlp' is unique in the tags. |
| `sigmahq_title_case` | Checks if a rule has a title with invalid casing. |
| `sigmahq_title_end` | Checks if a rule has a title that ends with a dot(.). |
| `sigmahq_title_length` | Checks if a rule has an excessively long title. |
| `sigmahq_title_start` | Checks if a rule title starts with the word 'Detect' or 'Detects'. |
| `sigmahq_trademark` | Checks if a rule title contains trademarked terms that should not be used. |
| `sigmahq_unknown_field` | Checks if a rule uses an unknown field. |
| `sigmahq_unsupported_regex_group_construct` | Checks if a rule uses an unsupported regular expression group constructs. |

## 🧬 Data

All the data value are in the json files in the tools directory

## 📜 Maintainer

This pipeline is currently maintained by:

* [François Hubaut (@frack113)](https://twitter.com/frack113)
* [Christian Burkard (@phantinuss)](https://twitter.com/phantinuss)
