from typing import Any, Dict

from sigma.rule import SigmaLogSource

from .base import SigmahqDataLoader, make_module_api


class _TaxonomyLoader(SigmahqDataLoader):
    _default_url = (
        "https://raw.githubusercontent.com/SigmaHQ/pySigma-validators-sigmaHQ/refs/heads/main/"
        "tools/sigmahq_taxonomy.json"
    )
    _cache_prefix = "sigmahq_taxonomy"
    _attr_prefix = "sigmahq_taxonomy_"

    def _parse(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        version = json_data.get("version", "unknown")
        fieldsname: Dict[str, Any] = {}
        redundant_fields: Dict[str, Any] = {}
        logsource_definition: Dict[str, Any] = {}

        if "taxonomy" in json_data:
            for info in json_data["taxonomy"].values():
                logsource = SigmaLogSource.from_dict(info["logsource"])
                logsource_key = f"{logsource.product}_{logsource.category}_{logsource.service}"
                field_info = info.get("field", {})
                fieldsname[logsource_key] = sorted(
                    field_info.get("native", []) + field_info.get("custom", []),
                    key=str.casefold,
                )
                redundant_fields[logsource_key] = field_info.get("redundant", [])
                if "definition" in info["logsource"]:
                    logsource_definition[logsource_key] = info["logsource"].get("definition")

        return {
            "sigmahq_taxonomy_version": version,
            "sigmahq_taxonomy_fieldsname": fieldsname,
            "sigmahq_taxonomy_redundant_fields": redundant_fields,
            "sigmahq_taxonomy_logsource_definition": logsource_definition,
        }


globals().update(make_module_api(_TaxonomyLoader))
