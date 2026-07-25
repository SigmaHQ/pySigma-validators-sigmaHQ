from typing import Any, Dict

from sigma.rule import SigmaLogSource

from .base import SigmahqDataLoader, make_module_api


class _FilenameLoader(SigmahqDataLoader):
    _default_url = (
        "https://raw.githubusercontent.com/SigmaHQ/pySigma-validators-sigmaHQ/refs/heads/main/"
        "tools/sigmahq_filename.json"
    )
    _cache_prefix = "sigmahq_filename"
    _attr_prefix = "sigmahq_filename_"

    def _parse(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        version = json_data.get("version", "unknown")
        pattern: Dict[str, str] = {}

        if "pattern" in json_data:
            for info in json_data["pattern"].values():
                if "logsource" not in info or "prefix" not in info:
                    continue
                logsource = SigmaLogSource.from_dict(info["logsource"])
                logsource_key = f"{logsource.product}_{logsource.category}_{logsource.service}"
                pattern[logsource_key] = info["prefix"]

        return {
            "sigmahq_filename_version": version,
            "sigmahq_filename_pattern": pattern,
        }


globals().update(make_module_api(_FilenameLoader))
