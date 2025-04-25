from dataclasses import dataclass
from typing import Dict, List, Tuple

from sigma.rule import SigmaLogSource
import json
import os
import pathlib


from .sigmahq_data import (
    sigmahq_logsource_filepattern,
    sigmahq_fieldsname,
    sigmahq_fieldsname_unicast,
    sigmahq_logsource_definition,
    windows_provider_name,
    windows_no_eventid,
)


def load_json_file(filename: str) -> dict:
    full_name = os.getcwd() + "/validator_json/" + filename
    if pathlib.Path(full_name).exists():
        with open(full_name, "r", encoding="UTF-8") as file:
            json_dict = json.load(file)
        return json_dict
    else:
        return None


def core_logsource(source: SigmaLogSource) -> SigmaLogSource:
    return SigmaLogSource(product=source.product, category=source.category, service=source.service)


def load_taxonomy_json(json_name: str) -> dict:
    json_dict = load_json_file(json_name)
    if json_dict is None:
        return None

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


def load_filepattern_json(json_name: str):
    json_dict = load_json_file(json_name)
    if json_dict is None:
        return None

    prefix_info = {}
    for value in json_dict["pattern"].values():
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        prefix_info[logsource] = value["prefix"]
    return prefix_info


def load_windows_json(json_name: str):
    json_dict = load_json_file(json_name)
    if json_dict is None:
        return None, None

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
    sigmahq_logsource_definition: Dict[SigmaLogSource, str] = {}

    def __init__(self) -> None:

        self.sigmahq_logsource_filepattern = sigmahq_logsource_filepattern
        self.sigma_fieldsname = sigmahq_fieldsname
        self.sigma_fieldsname_unicast = sigmahq_fieldsname_unicast
        self.sigmahq_logsource_definition = sigmahq_logsource_definition
        self.windows_provider_name = windows_provider_name
        self.windows_no_eventid = windows_no_eventid

        # self.sigma_taxonomy = load_taxonomy_json("sigma.json")
        # if self.sigma_taxonomy is not None:
        #     self.sigma_fieldsname = get_taxonomy_field(self.sigma_taxonomy)
        #     self.sigma_fieldsname_unicast = {
        #         k: [v.lower() for v in l] for k, l in self.sigma_fieldsname.items()
        #     }
        # else:
        #     self.sigma_fieldsname = None
        #     self.sigma_fieldsname_unicast = None

        # self.sigmahq_logsource_filepattern = load_filepattern_json("sigmahq_filename.json")
        # self.windows_no_eventid, self.windows_provider_name = load_windows_json(
        #    "sigmahq_windows_validator.json"
        # )
