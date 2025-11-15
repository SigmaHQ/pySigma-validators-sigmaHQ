import json
from pathlib import Path
from typing import Dict, List, Optional
from sigma.rule import SigmaLogSource
from .sigmahq_data import (
    taxonomy_version,
    ref_sigmahq_logsource_filepattern,
    file_pattern_version,
    ref_sigmahq_fieldsname,
    ref_sigmahq_redundant_field,
    ref_sigmahq_logsource_definition,
    windows_version,
    ref_windows_provider_name,
    ref_windows_no_eventid,
)
import requests


def core_logsource(source: SigmaLogSource) -> SigmaLogSource:
    """Create a core logsource with product, category and service."""
    return SigmaLogSource(product=source.product, category=source.category, service=source.service)


def key_logsource(source: dict) -> str:
    """Generate a unique key for a logsource dictionary."""
    product = source.get("product", "none") or "none"
    category = source.get("category", "none") or "none"
    service = source.get("service", "none") or "none"
    return f"{product}_{category}_{service}"


class ConfigHQ:
    """Loads SigmaHQ configuration from local JSON files if available, otherwise uses reference data.

    Supports both local and remote configuration sources with caching and fallback mechanisms.
    """

    JSON_FOLDER: str = "validator_json"
    JSON_NAME_TAXONOMY: str = "sigmahq_taxonomy.json"
    JSON_NAME_FILENAME: str = "sigmahq_filename.json"
    JSON_NAME_WINDOWS_PROVIDER: str = "sigmahq_windows_validator.json"

    def __init__(self, data_place: Optional[str] = None):
        # Initialize with internal reference data
        self.taxonomy_version = taxonomy_version
        self.sigmahq_redundant_fields = ref_sigmahq_redundant_field
        self.sigma_fieldsname = ref_sigmahq_fieldsname
        self.sigmahq_logsource_definition = ref_sigmahq_logsource_definition
        self.filename_version = file_pattern_version
        self.sigmahq_logsource_filepattern = ref_sigmahq_logsource_filepattern
        self.windows_version = windows_version
        self.windows_provider_name = ref_windows_provider_name
        self.windows_no_eventid = ref_windows_no_eventid

        # Determine configuration source
        self.config_dir: Optional[Path] = None
        self.config_url: Optional[str] = None

        if data_place is None:
            # Check default local folder
            default_path = Path.cwd() / self.JSON_FOLDER
            if default_path.exists():
                self.config_dir = default_path
        elif data_place.startswith("http://") or data_place.startswith("https://"):
            self.config_url = data_place.rstrip("/")
        else:
            self.config_dir = Path(data_place)

        # Load configuration if path exists
        if (
            self.config_dir is not None and self.config_dir.exists()
        ) or self.config_url is not None:
            self._load_sigma_json()
            self._load_filename_json()
            self._load_windows_provider_json()

    def _load_json(self, filename: str) -> Optional[dict]:
        """Load JSON data from either local file or remote URL with error handling."""
        if self.config_url:
            url = f"{self.config_url}/{filename}"
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                return response.json()
            except Exception as e:
                print(f"Error loading remote {filename}: {e}")
            return None
        elif self.config_dir:
            path = self.config_dir / filename
            if path.exists():
                try:
                    with path.open("r", encoding="UTF-8") as file:
                        return json.load(file)
                except Exception as e:
                    print(f"Error loading {filename}: {e}")
                    return None
            return None

    def _load_sigma_json(self):
        """Load taxonomy configuration from JSON."""
        json_dict = self._load_json(self.JSON_NAME_TAXONOMY)
        if not json_dict or "taxonomy" not in json_dict:
            return

        taxonomy_info: Dict[SigmaLogSource, List[str]] = {}
        taxonomy_definition: Dict[SigmaLogSource, Optional[str]] = {}
        taxonomy_redundant: Dict[SigmaLogSource, List[str]] = {}

        # Process taxonomy data
        temp = {key_logsource(v["logsource"]): v for v in json_dict["taxonomy"].values()}
        for key in sorted(temp.keys(), key=str.casefold):
            value = temp[key]
            logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
            fieldlist = sorted(
                value["field"]["native"] + value["field"]["custom"], key=str.casefold
            )
            taxonomy_info[logsource] = fieldlist
            taxonomy_definition[logsource] = value["logsource"].get("definition")
            taxonomy_redundant[logsource] = value["field"]["redundant"]

        self.taxonomy_version = json_dict["version"]
        self.sigma_fieldsname = taxonomy_info
        self.sigmahq_redundant_fields = taxonomy_redundant
        self.sigmahq_logsource_definition = taxonomy_definition

    def _load_filename_json(self):
        """Load filename pattern configuration from JSON."""
        json_dict = self._load_json(self.JSON_NAME_FILENAME)
        if not json_dict or "pattern" not in json_dict or "version" not in json_dict:
            return

        filename_info: Dict[SigmaLogSource, str] = {}
        temp = {key_logsource(v["logsource"]): v for v in json_dict["pattern"].values()}
        for key in sorted(temp.keys(), key=str.casefold):
            value = temp[key]
            logsource = core_logsource(SigmaLogSource.from_dict(value["logsource"]))
            filename_info[logsource] = value["prefix"]

        self.filename_version = json_dict["version"]
        self.sigmahq_logsource_filepattern = filename_info

    def _load_windows_provider_json(self):
        """Load Windows provider configuration from JSON."""
        json_dict = self._load_json(self.JSON_NAME_WINDOWS_PROVIDER)
        if (
            not json_dict
            or "category_provider_name" not in json_dict
            or "category_no_eventid" not in json_dict
        ):
            return

        windows_provider_name = dict()
        for category in sorted(json_dict["category_provider_name"], key=str.casefold):
            windows_provider_name[
                SigmaLogSource(product="windows", category=category, service=None)
            ] = json_dict["category_provider_name"][category]
        windows_no_eventid = sorted(json_dict["category_no_eventid"], key=str.casefold)
        self.windows_version = json_dict["version"]
        self.windows_provider_name = windows_provider_name
        self.windows_no_eventid = windows_no_eventid
