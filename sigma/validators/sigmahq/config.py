from dataclasses import dataclass
from typing import Dict, List, Optional

from sigma.rule import SigmaLogSource
import json
import os
import pathlib
from .sigmahq_data import (
    ref_sigmahq_logsource_filepattern,
    ref_sigmahq_fieldsname,
    ref_sigmahq_unneededfield,
    ref_sigmahq_logsource_definition,
    ref_windows_provider_name,
    ref_windows_no_eventid,
)
import requests


def core_logsource(source: SigmaLogSource) -> SigmaLogSource:
    return SigmaLogSource(product=source.product, category=source.category, service=source.service)


def key_logsource(source: dict) -> str:
    product = source["product"] if source["product"] else "none"
    category = source["category"] if source["category"] else "none"
    service = source["service"] if source["service"] else "none"
    return f"{product}_{category}_{service}"


def process_sigmahq_filename(url: str, json_name: str = "sigmahq_filename.json"):
    """
    Load and process 'sigmahq_filename.json' from the given url/path.
    Returns filename_version, filename_info.
    """

    filename_path = os.path.join(url, json_name)
    if filename_path.startswith("http://") or filename_path.startswith("https://"):
        response = requests.get(f"{url}/{json_name}")
        response.raise_for_status()
        json_dict = response.json()
    else:
        with open(filename_path, "r", encoding="UTF-8") as file:
            json_dict = json.load(file)

    filename_version = json_dict["version"]
    filename_info = dict()

    temp = {key_logsource(v["logsource"]): v for v in json_dict["pattern"].values()}
    for key in sorted(temp.keys(), key=str.casefold):
        value = temp[key]
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        filename_info[logsource] = value["prefix"]
    return filename_version, filename_info


def process_sigma_json(url: str, json_name: str = "sigma.json"):
    """
    Load and process 'sigma.json' from the given url/path.
    Returns taxonomy_version, taxonomy_info, taxonomy_definition.
    """
    filename_path = os.path.join(url, json_name)
    if filename_path.startswith("http://") or filename_path.startswith("https://"):
        response = requests.get(f"{url}/{json_name}")
        response.raise_for_status()
        json_dict = response.json()
    else:
        with open(filename_path, "r", encoding="UTF-8") as file:
            json_dict = json.load(file)

    taxonomy_version = json_dict["version"]
    taxonomy_info = dict()
    taxonomy_definition = dict()
    taxonomy_unneeded = dict()

    temp = {key_logsource(v["logsource"]): v for v in json_dict["taxonomy"].values()}
    for key in sorted(temp.keys(), key=str.casefold):
        value = temp[key]
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        fieldlist = []
        fieldlist.extend(value["field"]["native"])
        fieldlist.extend(value["field"]["custom"])
        taxonomy_info[logsource] = sorted(fieldlist, key=str.casefold)
        taxonomy_definition[logsource] = value["logsource"]["definition"]
        taxonomy_unneeded[logsource] = value["field"]["unneeded"]

    return taxonomy_version, taxonomy_info, taxonomy_definition, taxonomy_unneeded


def process_sigmahq_windows_validator(url: str, json_name: str = "sigmahq_windows_validator.json"):
    """
    Load and process 'sigmahq_windows_validator.json' from the given url/path.
    Returns windows_version, windows_provider_name, windows_no_eventid.
    """
    filename_path = os.path.join(url, json_name)
    if filename_path.startswith("http://") or filename_path.startswith("https://"):
        response = requests.get(f"{url}/{json_name}")
        response.raise_for_status()
        json_dict = response.json()
    else:
        with open(filename_path, "r", encoding="UTF-8") as file:
            json_dict = json.load(file)

    windows_version = json_dict["version"]
    windows_provider_name = dict()

    for category in sorted(json_dict["category_provider_name"], key=str.casefold):
        windows_provider_name[
            SigmaLogSource(product="windows", category=category, service=None)
        ] = json_dict["category_provider_name"][category]
    windows_no_eventid = sorted(json_dict["category_no_eventid"], key=str.casefold)
    return windows_version, windows_provider_name, windows_no_eventid


class ConfigHQ:
    JSON_FOLDER = "validator_json"
    sigma_fieldsname: Dict[SigmaLogSource, List[str]] = {}
    sigmahq_unneededfields: Dict[SigmaLogSource, List[str]] = {}

    sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = {}

    windows_no_eventid: List[str] = []
    windows_provider_name: Dict[SigmaLogSource, List[str]] = {}
    sigmahq_logsource_definition: Dict[SigmaLogSource, Optional[str]] = {}

    def __init__(self) -> None:

        local_path = os.path.join(os.getcwd(), self.JSON_FOLDER)

        if pathlib.Path(os.path.join(local_path, "sigma.json")).exists():
            (
                taxonomy_version,
                self.sigma_fieldsname,
                self.sigmahq_logsource_definition,
                self.sigmahq_unneededfields,
            ) = process_sigma_json(url=local_path)
        else:
            self.sigma_fieldsname = ref_sigmahq_fieldsname
            self.sigmahq_logsource_definition = ref_sigmahq_logsource_definition
            self.sigmahq_unneededfields = ref_sigmahq_unneededfield

        if pathlib.Path(os.path.join(local_path, "sigmahq_filename.json")).exists():
            filename_version, self.sigmahq_logsource_filepattern = process_sigmahq_filename(
                url=local_path
            )
        else:
            self.sigmahq_logsource_filepattern = ref_sigmahq_logsource_filepattern

        if pathlib.Path(os.path.join(local_path, "sigmahq_windows_validator.json")).exists():
            windows_version, self.windows_provider_name, self.windows_no_eventid = (
                process_sigmahq_windows_validator(url=local_path)
            )
        else:
            self.windows_provider_name = ref_windows_provider_name
            self.windows_no_eventid = ref_windows_no_eventid
