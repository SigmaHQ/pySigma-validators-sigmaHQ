# Version 0.2.0
# Author: frack113
# Date: 2025/06/06

import json
from sys import stderr, stdout
from pprint import pformat
from sigma.rule import SigmaLogSource
import sys
import os
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
    Returns taxonomy_version, taxonomy_info, taxonomy_definition, taxonomy_info_unicast.
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

    temp = {key_logsource(v["logsource"]): v for v in json_dict["taxonomy"].values()}
    for key in sorted(temp.keys(), key=str.casefold):
        value = temp[key]
        logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
        fieldlist = []
        fieldlist.extend(value["field"]["native"])
        fieldlist.extend(value["field"]["custom"])
        taxonomy_info[logsource] = sorted(fieldlist, key=str.casefold)
        taxonomy_definition[logsource] = value["logsource"]["definition"]

    taxonomy_info_unicast = {k: [v.lower() for v in l] for k, l in taxonomy_info.items()}
    return taxonomy_version, taxonomy_info, taxonomy_definition, taxonomy_info_unicast


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


def write_sigmahq_data_py(url, output_path="sigma/validators/sigmahq/sigmahq_data.py"):
    filename_version, filename_info = process_sigmahq_filename(url)
    taxonomy_version, taxonomy_info, taxonomy_definition, taxonomy_info_unicast = (
        process_sigma_json(url)
    )
    windows_version, windows_provider_name, windows_no_eventid = process_sigmahq_windows_validator(
        url
    )
    with open(output_path, "wt", encoding="utf-8", newline="") as file:
        print("from typing import Dict, List", file=file)
        print("from sigma.rule import SigmaLogSource", file=file)
        print("from typing import Optional", file=file)
        print(f'\nfile_pattern_version: str = "{filename_version}"', file=file)
        print(
            "ref_sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = "
            + pformat(filename_info, indent=4, sort_dicts=False),
            file=file,
        )
        print(f'\ntaxonomy_version: str = "{taxonomy_version}"', file=file)
        print(
            "ref_sigmahq_fieldsname: Dict[SigmaLogSource, List[str]] = "
            + pformat(taxonomy_info, indent=4, sort_dicts=False),
            file=file,
        )
        print(
            "ref_sigmahq_fieldsname_unicast: Dict[SigmaLogSource, List[str]] = "
            + pformat(taxonomy_info_unicast, indent=4, sort_dicts=False),
            file=file,
        )
        print(
            "ref_sigmahq_logsource_definition: Dict[SigmaLogSource, Optional[str]] = "
            + pformat(taxonomy_definition, indent=4, sort_dicts=False, width=200),
            file=file,
        )
        print(f'\nwindows_version: str = "{windows_version}"', file=file)
        print(
            "ref_windows_provider_name: Dict[SigmaLogSource, List[str]] = "
            + pformat(windows_provider_name, indent=4, sort_dicts=False),
            file=file,
        )
        print(
            "ref_windows_no_eventid: List[str] = "
            + pformat(windows_no_eventid, indent=4, sort_dicts=False),
            file=file,
        )


def main():
    if len(sys.argv) < 2:
        print("Usage: python update_ref.py <url>", file=stderr)
        sys.exit(1)
    file_url = sys.argv[1]
    print(f"Input URL: {file_url}")
    write_sigmahq_data_py(url=file_url)
    print("sigmahq data files have been processed and sigmahq_data.py has been generated.")


if __name__ == "__main__":
    main()
