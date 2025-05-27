# Version 0.0.1
# Author: frack113
# Date: 2025/04/25

import json
from sys import stderr, stdout
from pprint import pformat
from sigma.rule import SigmaLogSource


def core_logsource(source: SigmaLogSource) -> SigmaLogSource:
    return SigmaLogSource(product=source.product, category=source.category, service=source.service)


# Filename
with open("tools/sigmahq_filename.json", "r", encoding="UTF-8") as file:
    json_dict = json.load(file)

filename_version = json_dict["version"]
filename_info = {}
for value in json_dict["pattern"].values():
    logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
    filename_info[logsource] = value["prefix"]

with open("tools/sigma.json", "r", encoding="UTF-8") as file:
    json_dict = json.load(file)

taxonomy_version = json_dict["version"]
taxonomy_info = {}
taxonomy_definition = {}
for value in json_dict["taxonomy"].values():
    logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
    taxonomy_info[logsource] = value["field"]["native"]
    taxonomy_info[logsource].extend(value["field"]["custom"])
    taxonomy_definition[logsource] = value["logsource"]["definition"]

taxonomy_info_unicast = {k: [v.lower() for v in l] for k, l in taxonomy_info.items()}

with open("tools/sigmahq_windows_validator.json", "r", encoding="UTF-8") as file:
    json_dict = json.load(file)

windows_version = json_dict["version"]
windows_provider_name = dict()
for category in json_dict["category_provider_name"]:
    windows_provider_name[SigmaLogSource(product="windows", category=category, service=None)] = (
        json_dict["category_provider_name"][category]
    )
windows_no_eventid = json_dict["category_no_eventid"]


# python data
with open("sigma/validators/sigmahq/sigmahq_data.py", "wt", encoding="utf-8") as file:
    print("from typing import Dict, List", file=file)
    print("from sigma.rule import SigmaLogSource", file=file)
    print(f'\nfile_pattern_version: str = "{filename_version}"', file=file)
    print(
        "ref_sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = "
        + pformat(filename_info, indent=4, sort_dicts=True),
        file=file,
    )
    print(f'\ntaxonomy_version: str = "{taxonomy_version}"', file=file)
    print(
        "ref_sigmahq_fieldsname: Dict[SigmaLogSource, List[str]] = "
        + pformat(taxonomy_info, indent=4, sort_dicts=True),
        file=file,
    )
    print(
        "ref_sigmahq_fieldsname_unicast: Dict[SigmaLogSource, List[str]] = "
        + pformat(taxonomy_info_unicast, indent=4, sort_dicts=True),
        file=file,
    )
    print(
        "ref_sigmahq_logsource_definition: Dict[SigmaLogSource, str] = "
        + pformat(taxonomy_definition, indent=4, sort_dicts=True, width=200),
        file=file,
    )
    print(f'\nwindows_version: str = "{windows_version}"', file=file)
    print(
        "ref_windows_provider_name: Dict[SigmaLogSource, List[str]] = "
        + pformat(windows_provider_name, indent=4, sort_dicts=True),
        file=file,
    )
    print(
        "ref_windows_no_eventid: List[str] = "
        + pformat(windows_no_eventid, indent=4, sort_dicts=True),
        file=file,
    )
