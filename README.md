# pySigma_validators_sigmaHQ
![Tests](https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/frack113/b27ee1cbe964fb1a299cc20c3403f8c8/raw/pySigma-validators-sigmaHQ.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# 🌟 Purpose

Create all validators specific to the requirements of the SigmaHQ rules repository

# 🏗️ Validators

| Name | Description| severity |
| --- | --- | --- |
| sigmahq_categori_providername          | Checks if a rule uses a Provider_Name field with a windows   | MEDIUM |
| sigmahq_categorie_eventid              | Checks if a rule uses an EventID field with a windows        | MEDIUM |
| sigmahq_date_existence                 | Checks if rule has a data.                                   | MEDIUM |
| sigmahq_description_existence          | Checks if rule has a description.                            | MEDIUM |
| sigmahq_description_length             | Checks if rule has a description.                            | MEDIUM |
| sigmahq_falsepositives_banned_word     | Checks if rule falsepositive start with a banned word.       | MEDIUM |
| sigmahq_falsepositives_capital         | Checks if rule falsepositive start with a capital.           | MEDIUM |
| sigmahq_falsepositives_typo_word       | Checks if rule falsepositive start with a common typo error. | MEDIUM |
| sigmahq_field_duplicate_value          | Check uniques value in field list.                           | HIGH   |
| sigmahq_field_user                     | Check a User field use a localized name.                     | HIGH   |
| sigmahq_field_with_space               | Check field do not have a space.                             | HIGH   |
| sigmahq_fieldname_cast                 | Check field name have a cast error.                          | HIGH   |
| sigmahq_filename                       | Check rule filename match SigmaHQ standard.                  | MEDIUM |
| sigmahq_filename_prefix                | Check rule filename match SigmaHQ prefix standard.           | MEDIUM |
| sigmahq_invalid_all_modifier           | Check All modifier used with a single value.                 | HIGH   |
| sigmahq_invalid_field_source           | Check field Source use with Eventlog.                        | HIGH   |
| sigmahq_invalid_fieldname              | Check field name do not exist in the logsource.              | HIGH   |
| sigmahq_level_existence                | Checks if rule has a level.                                  | MEDIUM |
| sigmahq_link_description               | Checks if rule description use a link instead of references. | MEDIUM |
| sigmahq_logsource_known                | Checks if rule has known logsource.                          | HIGH   |
| sigmahq_noasterixofselection_condition | Check use '1/all of ' without asterix                        | MEDIUM |
| sigmahq_ofselection_condition          | Check use 'All/X of ' with only one selection                | LOW    |
| sigmahq_ofthem_condition               | Check use ' of them' with only one selection                 | LOW    |
| sigmahq_space_fieldname                | Check field name have a space.                               | HIGH   |
| sigmahq_status                         | Checks if rule has a status DEPRECATED or UNSUPPORTED.       | MEDIUM |
| sigmahq_status_existence               | Checks if rule has a status.                                 | HIGH   |
| sigmahq_sysmon_missing_eventid         | Checks if rule use windows sysmon service without EventID.   | HIGH   |
| sigmahq_title_case                     | Checks if rule title use capitalization.                     | MEDIUM |
| sigmahq_title_end                      | Checks if rule title end with a dot(.).                      | MEDIUM |
| sigmahq_title_length                   | Checks if rule has a title too long.                         | MEDIUM |
| sigmahq_title_start                    | Checks if rule title start with Detects.                     | MEDIUM |


# 🧬 Data

All the data value are in the config.py

# 📜 Maintainer

This pipelines is currently maintained by:
* [François Hubaut](https://github.com/frack113)
