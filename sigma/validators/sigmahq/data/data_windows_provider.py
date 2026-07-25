from typing import Any, Dict

from .base import SigmahqDataLoader, make_module_api


class _ProviderLoader(SigmahqDataLoader):
    _default_url = (
        "https://raw.githubusercontent.com/SigmaHQ/pySigma-validators-sigmaHQ/refs/heads/main/"
        "tools/sigmahq_windows_provider.json"
    )
    _cache_prefix = "sigmahq_provider"
    _attr_prefix = "sigmahq_provider_"

    def _parse(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "sigmahq_provider_version": json_data.get("version", "unknown"),
            "sigmahq_provider_name": json_data.get("category_provider_name", {}),
        }


globals().update(make_module_api(_ProviderLoader))
