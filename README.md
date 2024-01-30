# pySigma_validators_sigmaHQ
<!-- Workflow needs to be updated
![Tests](https://github.com/frack113/pySigma_validators_sigmaHQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/frack113/13cc99342f8578eac75f46f67e5fd023/raw/frack113-validators-coverage.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)
-->
# Purpose

Create all validators specific to the requirements of the SigmaHQ rules repository

# Validators

| Name | Description|
| --- | ---|
| sigmahq_fieldname_cast                | Check field name have a cast error.                          |
| sigmahq_invalid_fieldname             | Check field name do not exist in the logsource.              |
| sigmahq_invalid_field_source          | Check field Source use with Eventlog.                        |
| sigmahq_space_fieldname               | Check field name have a space.                               |
| sigmahq_filename_prefix               | Check rule filename match SigmaHQ prefix standard.           |
| sigmahq_filename                      | Check rule filename match SigmaHQ standard.                  |
| sigmahq_logsource_valid               | Checks if rule has valid logsource.                          |
| sigmahq_date_existence                | Checks if rule has a data.                                   |
| sigmahq_description_existence         | Checks if rule has a description.                            |
| sigmahq_description_length            | Checks if rule has a description.                            |
| sigmahq_falsepositives_banned_word    | Checks if rule falsepositive start with a banned word.       |
| sigmahq_falsepositives_capital        | Checks if rule falsepositive start with a capital.           |
| sigmahq_falsepositives_typo_word      | Checks if rule falsepositive start with a common typo error. |
| sigmahq_level_existence               | Checks if rule has a level.                                  |
| sigmahq_link_description              | Checks if rule description use a link instead of references. |
| sigmahq_status_deprecated             | Checks if rule has a status DEPRECATED.                      |
| sigmahq_status_existence              | Checks if rule has a status.                                 |
| sigmahq_status_unsupported            | Checks if rule has a status UNSUPPORTED.                     |
| sigmahq_title_case                    | Checks if rule title use capitalization.                     |
| sigmahq_title_end                     | Checks if rule end with a dot(.).                            |
| sigmahq_title_length                  | Checks if rule has a title length longer than 110.           |
| sigmahq_title_start                   | Checks if rule start with Detects.                           |

# Data

All the data value are in the config.py

# Maintainer

This pipelines is currently maintained by:
* [François Hubaut](https://github.com/frack113)
