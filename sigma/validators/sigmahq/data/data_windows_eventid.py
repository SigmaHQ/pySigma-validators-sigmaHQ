import json
import os
from pathlib import Path
from typing import Any, Optional, Dict, List, cast
from urllib.error import URLError
from urllib.request import urlopen

import diskcache

SIGMAHQ_EVENTID_URL = (
    "https://raw.githubusercontent.com/frack113/pySigma-validators-sigmaHQ/refs/heads/Refractor/"
    "tools/sigmahq_windows_eventid.json"
)

# Cache directory (in user's cache directory)
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "pysigma" / "sigmahq"

# Disk cache instance
_cache: Optional[diskcache.Cache] = None
_custom_url: Optional[str] = None
_custom_cache_dir: Optional[Path] = None


def _get_cache() -> diskcache.Cache:
    """Get or initialize the disk cache."""
    global _cache
    if _cache is None:
        cache_dir = _custom_cache_dir if _custom_cache_dir is not None else _DEFAULT_CACHE_DIR
        cache_dir.mkdir(parents=True, exist_ok=True)
        _cache = diskcache.Cache(str(cache_dir))
    return _cache


def _load_sigmahq_json() -> Dict[str, str]:
    """Load JSON data from the SigmaHQ eventid source (URL or local file) and cache it.

    Returns:
        dict: A dictionary containing the version and category_no_eventid data with keys:
            - 'sigmahq_category_no_eventid_version': The version string
            - 'sigmahq_category_no_eventid': The event ID mapping data (both strings)
    """
    cache = _get_cache()
    cache_key = f"sigmahq_eventid_{_custom_url or 'default'}"

    # Try to get from cache first
    cached_data = cache.get(cache_key)
    if cached_data is not None:
        return cast(dict[str, str], cached_data)

    url = _custom_url if _custom_url is not None else SIGMAHQ_EVENTID_URL

    try:
        # Check if it's a file path (doesn't start with http:// or https://)
        if not url.startswith(("http://", "https://")):
            with open(url, "r", encoding="utf-8") as f:
                json_data = json.load(f)
        else:
            with urlopen(url, timeout=30) as response:
                json_data = json.load(response)
    except (URLError, json.JSONDecodeError, OSError, IOError) as e:
        raise RuntimeError(f"Failed to load data: {e}") from e

    sigmahq_category_no_eventid_version = json_data["version"]
    sigmahq_category_no_eventid = json_data["category_no_eventid"]

    result = {
        "sigmahq_category_no_eventid_version": sigmahq_category_no_eventid_version or "unknown",
        "sigmahq_category_no_eventid": sigmahq_category_no_eventid,
    }

    # Store in cache
    cache.set(cache_key, result)

    return result


def _get_cached_data() -> Dict[str, str]:
    """Get cached data, loading it if necessary.

    Returns:
        dict: The cached data containing version and category_no_eventid strings.
    """
    return _load_sigmahq_json()


def __getattr__(name: str) -> Any:
    """Handle dynamic attribute access for module attributes.

    Args:
        name (str): The name of the attribute to retrieve.

    Returns:
        Any: The value of the requested attribute if it exists.
    Raises:
        AttributeError: If the attribute does not exist.
    """
    if name.startswith("sigmahq_category_"):
        data = _get_cached_data()
        if name in data:
            return data[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def clear_cache() -> None:
    """Clear the disk cache."""
    cache = _get_cache()
    cache.clear()


def set_url(url: str) -> None:
    """Set a custom URL for loading JSON data.

    Args:
        url (str): The URL to use for loading JSON data.
    """
    global _custom_url
    _custom_url = url
    clear_cache()


def set_cache_dir(cache_dir: str) -> None:
    """Set a custom cache directory for storing cached data.

    Args:
        cache_dir (str): The path to the custom cache directory.
    """
    global _cache, _custom_cache_dir
    _custom_cache_dir = Path(cache_dir)
    if _cache is not None:
        _cache.close()
        _cache = None
