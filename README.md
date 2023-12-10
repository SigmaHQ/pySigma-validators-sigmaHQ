# pySigma_validators_sigmaHQ
![Tests](https://github.com/frack113/pySigma_validators_sigmaHQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/frack113/13cc99342f8578eac75f46f67e5fd023/raw/frack113-validators-coverage.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# Purpose

Create all validators specific to the requirements of the SigmaHQ rules repository

# Validators

| Name | Description|
| --- | ---|
| sigmahq_fieldname_cast                | Check field name have a cast error.                          |
| sigmahq_invalid_fieldname             | Check field name do not exist in the logsource.              |
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

# sigmahq_filename_prefix

The validator uses 2 json files as references.
It is possible to use modified versions by placing them in a "tests" subdirectory of the command `sigma check.

## Json example

sigmahq_logsource_prefix.json
```json
{
    "driver_load_win": {
      "prefix": "driver_load_win_",
      "category": "driver_load",
      "product": "windows",
      "service": ""
    }
}
```

sigmahq_product_prefix.json
```json
{
  "windows": "win_"
}
```

# sigmahq_fieldname_cast sigmahq_invalid_fieldname

The validators uses a json as references.
It is possible to use modified versions by placing it in a "tests" subdirectory of the command `sigma check.

## Json example

sigmahq_product_cast.json
```json
  "win_ps_module": {
    "category": "ps_module",
    "product": "windows",
    "service": "",
    "field": [
      "ContextInfo",
      "UserData",
      "Payload"
    ]
  }
```

# sigmahq_logsource_valid

The validator uses a json as references.
It is possible to use modified versions by placing it in a "tests" subdirectory of the command `sigma check.
## Json example

sigmahq_logsource_valid.json
```json
{
  "logsource": [
    {"category": "process_tampering","product": "windows","service": ""},
    {"category": "process_termination","product": "macos","service": ""},
    {"category": "proxy","product": "","service": ""}
  ]
}
```

# Maintainer

This pipelines is currently maintained by:
* [François Hubaut](https://github.com/frack113)
