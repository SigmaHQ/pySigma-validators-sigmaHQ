# pySigma_validators_sigmaHQ
SigmaHq validators for pySigma 

# Validators

| Name | Description|
| --- | ---|
| sigmahq_filename_prefix               | Check rule filename match SigmaHQ prefix standard.           |
| sigmahq_filename                      | Check rule filename match SigmaHQ standard.                  |
| sigmahq_date_existence                | Checks if rule has a data.                                   |
| sigmahq_description_existence         | Checks if rule has a description.                            |
| sigmahq_description_length            | Checks if rule has a description.                            |
| sigmahq_falsepositives_banned_word    | Checks if rule falsepositive start with a banned word.       |
| sigmahq_falsepositives_capital        | Checks if rule falsepositive start with a capital.           |
| sigmahq_falsepositives_typo_word      | Checks if rule falsepositive start with a common typo error. |
| sigmahq_legal_trademark               | Checks if rule contains a legal trademark.                   |
| sigmahq_level_existence               | Checks if rule has a level.                                  |
| sigmahq_link_description              | Checks if rule description use a link instead of references. |
| sigmahq_status_deprecated             | Checks if rule has a status DEPRECATED.                      |
| sigmahq_status_existence              | Checks if rule has a status.                                 |
| sigmahq_status_unsupported            | Checks if rule has a status UNSUPPORTED.                     |
| sigmahq_title_case                    | Checks if rule title use capitalization.                     |
| sigmahq_title_end                     | Checks if rule end with a dot(.).                            |
| sigmahq_title_length                  | Checks if rule has a title length longer than 110.           |
| sigmahq_title_start                   | Checks if rule start with Detects.                           |

This pipelines is currently maintained by:
* [François Hubaut](https://github.com/frack113)
