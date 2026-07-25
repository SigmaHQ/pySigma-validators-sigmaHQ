from typing import Any, Dict

from .base import SigmahqDataLoader


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


_loader = _ProviderLoader()


def __getattr__(name: str) -> Any:
    return _loader.get_attr(name, __name__)


def clear_cache() -> None:
    _loader.clear_cache()


def set_url(url: str) -> None:
    _loader.set_url(url)


def set_cache_dir(cache_dir: str) -> None:
    _loader.set_cache_dir(cache_dir)
