import csv
import io
from typing import Any, Dict

from .base import SigmahqDataLoader, make_module_api


class _AtomicRedTeamLoader(SigmahqDataLoader):
    _default_url = (
        "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/"
        "atomics/Indexes/Indexes-CSV/index.csv"
    )
    _cache_prefix = "sigmahq_atomic_red_team"
    _attr_prefix = "sigmahq_atomic_red_team_"

    def _fetch(self, url: str) -> str:
        """Fetch the index as text. The CSV index is not valid JSON, so the JSON
        fetcher of the base class cannot be used."""
        import warnings
        from urllib.error import URLError
        from urllib.request import urlopen

        try:
            if not url.startswith(("http://", "https://")):
                with open(url, encoding="utf-8") as f:
                    return f.read()
            if url.startswith("http://"):
                warnings.warn(
                    f"Unencrypted HTTP URL used for data loading: {url}. "
                    f"Prefer HTTPS to avoid tampered validation data.",
                    stacklevel=3,
                )
            # noqa: S310 - http/https are the only accepted schemes; URLs come from
            # trusted application configuration (set_url), not untrusted input.
            with urlopen(url, timeout=30) as response:  # noqa: S310
                return response.read().decode("utf-8")
        except (URLError, OSError) as e:
            raise RuntimeError(f"Failed to load data: {e}") from e

    def _parse(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def _load_cached(self) -> Dict[str, Any]:
        cache = self._get_cache()
        cache_key = f"{self._cache_prefix}_{self._custom_url or 'default'}"

        cached_data = cache.get(cache_key)
        if cached_data is not None:
            return cached_data

        url = self._custom_url if self._custom_url is not None else self._default_url
        result = self._parse_csv(self._fetch(url))

        cache.set(cache_key, result)
        return result

    def _parse_csv(self, text: str) -> Dict[str, Any]:
        """Map every atomic GUID to its test name.

        The index repeats a test once per tactic, so the same GUID shows up
        several times. Those repetitions always agree on the name, hence the
        first occurrence wins and the mapping stays unambiguous.
        """
        index: Dict[str, str] = {}
        for row in csv.DictReader(io.StringIO(text)):
            guid = (row.get("Test GUID") or "").strip()
            if not guid:
                continue
            index.setdefault(guid, (row.get("Test Name") or "").strip())
        return {"sigmahq_atomic_red_team_test_name_by_guid": index}


globals().update(make_module_api(_AtomicRedTeamLoader))
