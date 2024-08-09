# pySigma_validators_sigmaHQ
![Tests](https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/frack113/b27ee1cbe964fb1a299cc20c3403f8c8/raw/pySigma-validators-sigmaHQ.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# 🌟 Purpose

Create all validators specific to the requirements of the SigmaHQ rules repository

# 🏗️ Validators

| Name | Description| severity |
| --- | --- | --- |
| sigmahq_categori_providername          | Checks if a rule uses a Provider_Name field with a windows                   | medium |
| sigmahq_categorie_eventid              | Checks if a rule uses an EventID field with a windows                        | medium |
| sigmahq_date_existence                 | Checks if rule has a data field.                                             | medium |
| sigmahq_description_existence          | Checks if rule has a description field.                                      | medium |
| sigmahq_description_length             | Checks if a rule has a has an overly brief description.                      | medium |
| sigmahq_falsepositives_banned_word     | Checks if rule falsepositive start with a banned word.                       | medium |
| sigmahq_falsepositives_capital         | Checks if rule falsepositive start with a capital.                           | medium |
| sigmahq_falsepositives_typo_word       | Checks if rule falsepositive start with a common typo error.                 | medium |
| sigmahq_field_duplicate_value          | Check uniques value in field list.                                           | high   |
| sigmahq_field_user                     | Check a User field use a localized name.                                     | high   |
| sigmahq_field_with_space               | Check field do not have a space.                                             | high   |
| sigmahq_fieldname_cast                 | Check field name have a cast error.                                          | high   |
| sigmahq_filename                       | Check rule filename match SigmaHQ standard.                                  | medium |
| sigmahq_filename_prefix                | Check rule filename match SigmaHQ prefix standard.                           | medium |
| sigmahq_invalid_all_modifier           | Check All modifier used with a single value.                                 | high   |
| sigmahq_invalid_field_source           | Check field Source use with Eventlog.                                        | high   |
| sigmahq_invalid_fieldname              | Check field name do not exist in the logsource.                              | high   |
| sigmahq_level_existence                | Checks if rule has a level field.                                            | medium |
| sigmahq_link_description               | Checks if rule description use a link instead of references.                 | medium |
| sigmahq_logsource_unknown              | Checks if a rule uses an unknown logsource.                                  | high   |
| sigmahq_noasterixofselection_condition | Check use '1/all of ' without asterix                                        | medium |
| sigmahq_ofselection_condition          | Check use 'All/X of ' with only one selection                                | low    |
| sigmahq_ofthem_condition               | Check use ' of them' with only one selection                                 | low    |
| sigmahq_space_fieldname                | Check field name have a space.                                               | high   |
| sigmahq_status                         | Checks if rule has a status field with the value Deprecated or Unsupported.  | medium |
| sigmahq_status_existence               | Checks if a rule is missing the status field.                                | high   |
| sigmahq_sysmon_missing_eventid         | Checks if rule uses windows sysmon service without EventID.                  | high   |
| sigmahq_title_case                     | Checks if a rule has a title with invalid casing.                            | medium |
| sigmahq_title_end                      | Checks if a rule has title that ends with a dot(.).                          | medium |
| sigmahq_title_length                   | Checks if a rule has an excessively long title.                              | medium |
| sigmahq_title_start                    | Checks if a rule title starts with the word 'Detect' or 'Detects'.           | medium |
| sigmahq_unknown_field                  | Checks if a rule uses an unknown field.                                      | medium |

# 🧬 Data

All the data value are in the config.py

# 📜 Maintainer

This pipelines is currently maintained by:
* [François Hubaut](https://github.com/frack113)
