# pySigma_validators_sigmaHQ
![Tests](https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/frack113/b27ee1cbe964fb1a299cc20c3403f8c8/raw/pySigma-validators-sigmaHQ.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# Purpose

Create all validators specific to the requirements of the SigmaHQ rules repository

# Validators

| Name | Description|
| --- | ---|
| sigmahq_date_existence                | Checks if rule has a data.                                   |
| sigmahq_description_existence         | Checks if rule has a description.                            |
| sigmahq_description_length            | Checks if rule has a description.                            |
| sigmahq_falsepositives_banned_word    | Checks if rule falsepositive start with a banned word.       |
| sigmahq_falsepositives_capital        | Checks if rule falsepositive start with a capital.           |
| sigmahq_falsepositives_typo_word      | Checks if rule falsepositive start with a common typo error. |
| sigmahq_field_duplicate_value         | Check uniques value in field list.                           |
| sigmahq_fieldname_cast                | Check field name have a cast error.                          |
| sigmahq_filename                      | Check rule filename match SigmaHQ standard.                  |
| sigmahq_filename_prefix               | Check rule filename match SigmaHQ prefix standard.           |
| sigmahq_invalid_all_modifier          | Check All modifier used with a single value.                 |
| sigmahq_invalid_field_source          | Check field Source use with Eventlog.                        |
| sigmahq_invalid_fieldname             | Check field name do not exist in the logsource.              |
| sigmahq_level_existence               | Checks if rule has a level.                                  |
| sigmahq_link_description              | Checks if rule description use a link instead of references. |
| sigmahq_logsource_coherent            | Checks if rule has Coherent logsource.                       |
| sigmahq_logsource_known               | Checks if rule has known logsource.                          |
| sigmahq_space_fieldname               | Check field name have a space.                               |
| sigmahq_status_deprecated             | Checks if rule has a status DEPRECATED.                      |
| sigmahq_status_existence              | Checks if rule has a status.                                 |
| sigmahq_status_unsupported            | Checks if rule has a status UNSUPPORTED.                     |
| sigmahq_title_case                    | Checks if rule title use capitalization.                     |
| sigmahq_title_end                     | Checks if rule title end with a dot(.).                      |
| sigmahq_title_length                  | Checks if rule has a title too long.                         |
| sigmahq_title_start                   | Checks if rule title start with Detects.                     |

# Data

All the data value are in the config.py

# Maintainer

This pipelines is currently maintained by:
* [François Hubaut](https://github.com/frack113)
