from dataclasses import dataclass
from typing import Dict, List, Tuple

from sigma.rule import SigmaLogSource
import json
import os
import pathlib
import requests


def load_remote_json(url: str, filename: str) -> dict:
    full_name = os.getcwd() + "/validator_json/" + filename
    if pathlib.Path(full_name).exists():
        with open(full_name, "r", encoding="UTF-8") as file:
            json_dict = json.load(file)
    else:
        r = requests.get(url)
        json_dict = json.loads(r.content.decode(encoding="UTF-8"))
    return json_dict


def core_logsource(source: SigmaLogSource) -> SigmaLogSource:
    return SigmaLogSource(product=source.product, category=source.category, service=source.service)


def load_taxonomy_json(url: str, json_name: str) -> dict:
    json_dict = load_remote_json(url, json_name)
    info = {}
    for value in json_dict["taxonomy"].values():
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        info[logsource] = value
    return info


def get_taxonomy_field(sigma: dict) -> dict:
    field_info = {}
    for key, value in sigma.items():
        field_info[key] = value["field"]["native"]
        field_info[key].extend(value["field"]["custom"])
    return field_info


def load_filepattern_json(url: str, json_name: str):
    prefix_info = {}
    json_dict = load_remote_json(url, json_name)
    for value in json_dict["pattern"].values():
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        prefix_info[logsource] = value["prefix"]
    return prefix_info


def load_windows_json(url: str, json_name: str):
    json_dict = load_remote_json(url, json_name)
    data = dict()
    for category in json_dict["category_provider_name"]:
        data[SigmaLogSource(product="windows", category=category, service=None)] = json_dict[
            "category_provider_name"
        ][category]
    return json_dict["category_no_eventid"], data


class ConfigHQ:
    sigma_taxonomy: Dict = {}
    sigma_fieldsname: Dict[SigmaLogSource, List[str]] = {}
    sigma_fieldsname_unicast: Dict[SigmaLogSource, List[str]] = {}

    sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = {}

    windows_no_eventid: List[str] = []
    windows_provider_name: Dict[SigmaLogSource, List[str]] = {}

    def __init__(self) -> None:
        self.sigma_taxonomy = load_taxonomy_json(
            url="https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/raw/refs/heads/main/validator_json/sigma.json",
            json_name="sigma.json",
        )
        self.sigma_fieldsname = get_taxonomy_field(self.sigma_taxonomy)
        self.sigma_fieldsname_unicast = {
            k: [v.lower() for v in l] for k, l in self.sigma_fieldsname.items()
        }

        self.sigmahq_logsource_filepattern = load_filepattern_json(
            url="https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/raw/refs/heads/main/validator_json/sigmahq_filename.json",
            json_name="sigmahq_filename.json",
        )
        self.windows_no_eventid, self.windows_provider_name = load_windows_json(
            url="https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/raw/refs/heads/main/validator_json/sigmahq_windows_validator.json",
            json_name="sigmahq_windows_validator.json",
        )
