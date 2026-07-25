from typing import Any, Dict

from .base import SigmahqDataLoader, make_module_api


class _EventIdLoader(SigmahqDataLoader):
    _default_url = (
        "https://raw.githubusercontent.com/SigmaHQ/pySigma-validators-sigmaHQ/refs/heads/main/"
        "tools/sigmahq_windows_eventid.json"
    )
    _cache_prefix = "sigmahq_eventid"
    _attr_prefix = "sigmahq_category_"

    def _parse(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "sigmahq_category_no_eventid_version": json_data.get("version", "unknown"),
            "sigmahq_category_no_eventid": json_data.get("category_no_eventid", []),
        }


globals().update(make_module_api(_EventIdLoader))
