from dataclasses import dataclass
from typing import Dict, List

from sigma.rule import SigmaLogSource
import json


def load_remote_json(url: str, filename: str) -> dict:
    # url to check
    # else
    full_name = "validator_json/" + filename
    with open(full_name, "r", encoding="UTF-8") as file:
        json_dict = json.load(file)
    return json_dict


def load_taxonomy_json(json_name: str) -> dict:
    field_info = {}
    common_info = {}
    addon_info = {}

    json_dict = load_remote_json("github", json_name)
    for key in json_dict["common"]:
        info = json_dict["common"][key]
        logsource = SigmaLogSource(
            product=info["product"], category=info["category"], service=info["service"]
        )
        common_info[logsource] = info["data"]

    for key in json_dict["addon"]:
        info = json_dict["addon"][key]
        logsource = SigmaLogSource(
            product=info["product"], category=info["category"], service=info["service"]
        )
        addon_info[logsource] = info["data"]

    for key in json_dict["field"]:
        info = json_dict["field"][key]
        logsource = SigmaLogSource(
            product=info["product"], category=info["category"], service=info["service"]
        )
        field_info[logsource] = info["data"]

        if len(info["data"]) > 0:
            if (
                logsource.product
                and SigmaLogSource(product=logsource.product) in common_info
            ):
                field_info[logsource] += common_info[
                    SigmaLogSource(product=logsource.product)
                ]
            if logsource in addon_info:
                field_info[logsource] += addon_info[logsource]
            if "Hashes" in info["data"] or "Hash" in info["data"]:
                field_info[logsource] += ["md5", "sha1", "sha256", "Imphash"]

    return field_info


def load_filepattern_json(json_name):
    json_dict = load_remote_json("github", json_name)
    data = {}
    for key in json_dict["logsource"]:
        data[
            SigmaLogSource(
                product=json_dict["logsource"][key]["product"],
                category=json_dict["logsource"][key]["category"],
                service=json_dict["logsource"][key]["service"],
            )
        ] = json_dict["logsource"][key]["prefix"]
    return data, json_dict["product"]


def load_windows_json(json_name):
    json_dict = load_remote_json("github", json_name)
    data = dict()
    for category in json_dict["category_provider_name"]:
        data[SigmaLogSource(product="windows", category=category, service=None)] = (
            json_dict["category_provider_name"][category]
        )
    return json_dict["category_no_eventid"], data


class ConfigHQ:
    sigma_taxonomy: Dict[SigmaLogSource, List[str]] = {}
    sigma_taxonomy_unicast: Dict[SigmaLogSource, List[str]] = {}
    title_max_length = 110
    sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = {}
    sigmahq_product_prefix: Dict[str, str] = {}
    windows_no_eventid: List[str] = []
    windows_provider_name: Dict[SigmaLogSource, List[str]] = {}

    def __init__(self) -> None:

        self.sigma_taxonomy = load_taxonomy_json("sigma_taxonomy.json")
        self.sigma_taxonomy_unicast = {
            k: [v.lower() for v in l] for k, l in self.sigma_taxonomy.items()
        }

        self.sigmahq_logsource_filepattern, self.sigmahq_product_prefix = (
            load_filepattern_json("sigmahq_filepattern.json")
        )
        self.windows_no_eventid, self.windows_provider_name = load_windows_json(
            "sigmahq_windows_validator.json"
        )
