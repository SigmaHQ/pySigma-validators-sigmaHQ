from dataclasses import dataclass
import json
import pathlib
from typing import Dict, List, Optional, Any
from sigma.rule import SigmaLogSource
from .sigmahq_data import (
    ref_sigmahq_logsource_filepattern,
    ref_sigmahq_fieldsname,
    ref_sigmahq_redundant_field,
    ref_sigmahq_logsource_definition,
    ref_windows_provider_name,
    ref_windows_no_eventid,
)
import requests


def core_logsource(source: SigmaLogSource) -> SigmaLogSource:
    return SigmaLogSource(product=source.product, category=source.category, service=source.service)


def key_logsource(source: Dict[str, Any]) -> str:
    product = source["product"] if source["product"] else "none"
    category = source["category"] if source["category"] else "none"
    service = source["service"] if source["service"] else "none"
    return f"{product}_{category}_{service}"


class ConfigHQ:
    """Loads SigmaHQ configuration from local JSON files if available, otherwise uses reference data."""

    JSON_FOLDER: str = "validator_json"
    JSON_NAME_TAXONOMY: str = "sigmahq_taxonomy.json"
    JSON_NAME_FILENAME: str = "sigmahq_filename.json"
    JSON_NAME_WINDOWS_PROVIDER: str = "sigmahq_windows_validator.json"

    taxonomy_version: str = "0.0.0"
    sigma_fieldsname: Dict[SigmaLogSource, List[str]] = {}
    sigmahq_redundant_fields: Dict[SigmaLogSource, List[str]] = {}

    filename_version: str = "0.0.0"
    sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = {}

    windows_version: str = "0.0.0"
    windows_no_eventid: List[str] = []
    windows_provider_name: Dict[SigmaLogSource, List[str]] = {}
    sigmahq_logsource_definition: Dict[SigmaLogSource, Optional[str]] = {}

    def __init__(self, config_dir: Optional[str] = None):
        # Accept both local path and remote URL for config_dir
        self.is_remote = False
        if config_dir and (config_dir.startswith("http://") or config_dir.startswith("https://")):
            self.remote_url = config_dir.rstrip("/")
            self.is_remote = True
        else:
            self.local_dir = (
                pathlib.Path(config_dir)
                if config_dir
                else pathlib.Path.cwd() / pathlib.Path(self.JSON_FOLDER)
            )

        self._load_sigma_json()
        self._load_filename_json()
        self._load_windows_provider_json()

    def _load_json(self, filename: str) -> Optional[Dict[str, Any]]:
        if self.is_remote:
            file_url = f"{self.remote_url}/{filename}"
            try:
                response = requests.get(file_url)
                response.raise_for_status()
                # Type cast the response to avoid mypy warnings
                result = response.json()
                return result  # type: ignore
            except Exception as e:
                print(f"Error loading remote {filename}: {e}")
            return None
        else:
            path = self.local_dir / filename
            if path.exists():
                try:
                    with path.open("r", encoding="UTF-8") as file:
                        # Use type: ignore for json.load as well
                        return json.load(file)  # type: ignore
                except Exception as e:
                    print(f"Error loading {filename}: {e}")
            return None

    def _load_sigma_json(self) -> None:
        json_dict = self._load_json(self.JSON_NAME_TAXONOMY)
        if json_dict:
            taxonomy_info: Dict[SigmaLogSource, List[str]] = {}
            taxonomy_definition: Dict[SigmaLogSource, Optional[str]] = {}
            taxonomy_redundant: Dict[SigmaLogSource, List[str]] = {}
            temp = {key_logsource(v["logsource"]): v for v in json_dict["taxonomy"].values()}
            for key in sorted(temp.keys(), key=str.casefold):
                value = temp[key]
                logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
                fieldlist = []
                fieldlist.extend(value["field"]["native"])
                fieldlist.extend(value["field"]["custom"])
                taxonomy_info[logsource] = sorted(fieldlist, key=str.casefold)
                taxonomy_definition[logsource] = value["logsource"]["definition"]
                taxonomy_redundant[logsource] = value["field"]["redundant"]
            self.taxonomy_version = json_dict["version"]
            self.sigmahq_redundant_fields = taxonomy_redundant
            self.sigma_fieldsname = taxonomy_info
            self.sigmahq_logsource_definition = taxonomy_definition
        else:
            self.taxonomy_version = "0.0.0"
            self.sigmahq_redundant_fields = ref_sigmahq_redundant_field
            self.sigma_fieldsname = ref_sigmahq_fieldsname
            self.sigmahq_logsource_definition = ref_sigmahq_logsource_definition

    def _load_filename_json(self) -> None:
        json_dict = self._load_json(self.JSON_NAME_FILENAME)
        if json_dict:

            filename_info: Dict[SigmaLogSource, str] = {}
            temp = {key_logsource(v["logsource"]): v for v in json_dict["pattern"].values()}
            for key in sorted(temp.keys(), key=str.casefold):
                value = temp[key]
                logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
                filename_info[logsource] = value["prefix"]
            self.filename_version = json_dict["version"]
            self.sigmahq_logsource_filepattern = filename_info
        else:
            self.filename_version = "0.0.0"
            self.sigmahq_logsource_filepattern = ref_sigmahq_logsource_filepattern

    def _load_windows_provider_json(self) -> None:
        json_dict = self._load_json(self.JSON_NAME_WINDOWS_PROVIDER)
        if json_dict:
            windows_provider_name: Dict[SigmaLogSource, List[str]] = {}
            for category in sorted(json_dict["category_provider_name"], key=str.casefold):
                windows_provider_name[
                    SigmaLogSource(product="windows", category=category, service=None)
                ] = json_dict["category_provider_name"][category]
            windows_no_eventid = sorted(json_dict["category_no_eventid"], key=str.casefold)
            self.windows_version = json_dict["version"]
            self.windows_provider_name = windows_provider_name
            self.windows_no_eventid = windows_no_eventid
        else:
            self.windows_version = "0.0.0"
            self.windows_provider_name = ref_windows_provider_name
            self.windows_no_eventid = ref_windows_no_eventid
