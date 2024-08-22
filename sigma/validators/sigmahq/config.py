from dataclasses import dataclass
from typing import Dict, List, Tuple

from sigma.rule import SigmaLogSource
import json
import os


def load_remote_json(url: str, filename: str) -> dict:
    # url to check
    # else
    full_name = os.getcwd() + "/validator_json/" + filename
    with open(full_name, "r", encoding="UTF-8") as file:
        json_dict = json.load(file)
    return json_dict


def core_logsource(source: SigmaLogSource) -> SigmaLogSource:
    return SigmaLogSource(
        product=source.product, category=source.category, service=source.service
    )


def load_taxonomy_json(json_name: str) -> dict:
    field_info = {}
    json_dict = load_remote_json("github", json_name)
    for value in json_dict["taxonomy"].values():
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        field_info[logsource] = value["field"]["natif"]
        field_info[logsource].extend(value["field"]["custom"])
    return field_info


def load_filepattern_json(json_name):
    prefix_info = {}
    json_dict = load_remote_json("github", json_name)
    for value in json_dict["pattern"].values():
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        prefix_info[logsource] = value["prefix"]
    return prefix_info


def load_windows_json(json_name):
    json_dict = load_remote_json("github", json_name)
    data = dict()
    for category in json_dict["category_provider_name"]:
        data[SigmaLogSource(product="windows", category=category, service=None)] = (
            json_dict["category_provider_name"][category]
        )
    return json_dict["category_no_eventid"], data


class ConfigHQ:
    title_max_length = 120

    sigma_taxonomy: Dict[SigmaLogSource, List[str]] = {}
    sigma_taxonomy_unicast: Dict[SigmaLogSource, List[str]] = {}

    sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = {}

    windows_no_eventid: List[str] = []
    windows_provider_name: Dict[SigmaLogSource, List[str]] = {}

    sigmahq_unsupported_regex_group_constructs: Tuple[str] = (
        "(?=",
        "(?!",
        "(?<=",
        "(?<!",
        "(?>",
    )

    def __init__(self) -> None:
        self.sigma_taxonomy = load_taxonomy_json("sigma.json")
        self.sigma_taxonomy_unicast = {
            k: [v.lower() for v in l] for k, l in self.sigma_taxonomy.items()
        }

        self.sigmahq_logsource_filepattern = load_filepattern_json(
            "sigmahq_filename.json"
        )
        self.windows_no_eventid, self.windows_provider_name = load_windows_json(
            "sigmahq_windows_validator.json"
        )
