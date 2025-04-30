from dataclasses import dataclass
from typing import Dict, List, Tuple

from sigma.rule import SigmaLogSource
import json
import os
import pathlib
from .sigmahq_data import (
    ref_sigmahq_logsource_filepattern,
    ref_sigmahq_fieldsname,
    ref_sigmahq_fieldsname_unicast,
    ref_sigmahq_logsource_definition,
    ref_windows_provider_name,
    ref_windows_no_eventid,
)


def core_logsource(source: SigmaLogSource) -> SigmaLogSource:
    return SigmaLogSource(product=source.product, category=source.category, service=source.service)


def load_sigma_json(local_path: str):
    with open(local_path + "sigma.json", "r", encoding="UTF-8") as file:
        json_dict = json.load(file)
    taxonomy_info = {}
    taxonomy_definition = {}
    for value in json_dict["taxonomy"].values():
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        taxonomy_info[logsource] = value["field"]["native"]
        taxonomy_info[logsource].extend(value["field"]["custom"])
        taxonomy_definition[logsource] = value["logsource"]["definition"]
    taxonomy_info_unicast = {k: [v.lower() for v in l] for k, l in taxonomy_info.items()}
    return taxonomy_info, taxonomy_info_unicast, taxonomy_definition


def load_sigmahq_filename_json(local_path: str):
    with open(local_path + "sigmahq_filename.json", "r", encoding="UTF-8") as file:
        json_dict = json.load(file)
    filename_info = {}
    for value in json_dict["pattern"].values():
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        filename_info[logsource] = value["prefix"]
    return filename_info


def load_windows_provider_json(local_path: str):
    with open(local_path + "sigmahq_windows_validator.json", "r", encoding="UTF-8") as file:
        json_dict = json.load(file)
    windows_provider_name = dict()
    for category in json_dict["category_provider_name"]:
        windows_provider_name[
            SigmaLogSource(product="windows", category=category, service=None)
        ] = json_dict["category_provider_name"][category]
    windows_no_eventid = json_dict["category_no_eventid"]
    return windows_provider_name, windows_no_eventid


class ConfigHQ:
    sigma_fieldsname: Dict[SigmaLogSource, List[str]] = {}
    sigma_fieldsname_unicast: Dict[SigmaLogSource, List[str]] = {}

    sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = {}

    windows_no_eventid: List[str] = []
    windows_provider_name: Dict[SigmaLogSource, List[str]] = {}
    sigmahq_logsource_definition: Dict[SigmaLogSource, str] = {}

    def __init__(self) -> None:

        local_path = os.path.join(os.getcwd(), "validator_json")

        if pathlib.Path(os.path.join(local_path, "sigma.json")).exists():
            (
                self.sigma_fieldsname,
                self.sigma_fieldsname_unicast,
                self.sigmahq_logsource_definition,
            ) = load_sigma_json(local_path)
        else:
            self.sigma_fieldsname = ref_sigmahq_fieldsname
            self.sigma_fieldsname_unicast = ref_sigmahq_fieldsname_unicast
            self.sigmahq_logsource_definition = ref_sigmahq_logsource_definition

        if pathlib.Path(local_path + "sigmahq_filename.json").exists():
            self.sigmahq_logsource_filepattern = load_sigmahq_filename_json(local_path)
        else:
            self.sigmahq_logsource_filepattern = ref_sigmahq_logsource_filepattern

        if pathlib.Path(local_path + "sigmahq_windows_validator.json").exists():
            self.windows_provider_name, self.windows_no_eventid = load_windows_provider_json(
                local_path
            )
        else:
            self.windows_provider_name = ref_windows_provider_name
            self.windows_no_eventid = ref_windows_no_eventid
