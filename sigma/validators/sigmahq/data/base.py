import http.client
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional, cast
from urllib.error import URLError
from urllib.request import urlopen

import diskcache

_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "pysigma" / "sigmahq"


class _JSONDisk(diskcache.Disk):
    def store(self, value, read, key=None):
        try:
            data = json.dumps(value, ensure_ascii=False).encode("utf-8")
            return len(data), 1, None, data
        except (TypeError, ValueError):
            return super().store(value, read, key=key)

    def fetch(self, mode, filename, value, expire):
        if mode == 1:
            return json.loads(value.decode("utf-8"))
        return super().fetch(mode, filename, value, expire)


class SigmahqDataLoader(ABC):
    _default_url: str
    _cache_prefix: str
    _attr_prefix: str

    def __init__(self) -> None:
        self._cache: Optional[diskcache.Cache] = None
        self._custom_url: Optional[str] = None
        self._custom_cache_dir: Optional[Path] = None

    def _get_cache(self) -> diskcache.Cache:
        if self._cache is None:
            cache_dir = (
                self._custom_cache_dir if self._custom_cache_dir is not None else _DEFAULT_CACHE_DIR
            )
            cache_dir.mkdir(parents=True, exist_ok=True)
            self._cache = diskcache.Cache(str(cache_dir), disk=_JSONDisk)
        return self._cache

    def _fetch_json(self, url: str) -> Dict[str, Any]:
        try:
            if not url.startswith(("http://", "https://")):
                with open(url, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                with urlopen(url, timeout=30) as response:  # noqa: S310
                    return json.load(response)
        except (
            URLError,
            json.JSONDecodeError,
            OSError,
            IOError,
            http.client.HTTPException,
        ) as e:
            raise RuntimeError(f"Failed to load data: {e}") from e

    @abstractmethod
    def _parse(self, json_data: Dict[str, Any]) -> Dict[str, Any]: ...

    def _load_cached(self) -> Dict[str, Any]:
        cache = self._get_cache()
        cache_key = f"{self._cache_prefix}_{self._custom_url or 'default'}"

        cached_data = cache.get(cache_key)
        if cached_data is not None:
            return cast(Dict[str, Any], cached_data)

        url = self._custom_url if self._custom_url is not None else self._default_url
        json_data = self._fetch_json(url)
        result = self._parse(json_data)

        cache.set(cache_key, result)
        return result

    def get_attr(self, name: str, module_name: str = "") -> Any:
        if name.startswith(self._attr_prefix):
            data = self._load_cached()
            if name in data:
                return data[name]
        raise AttributeError(f"module '{module_name or __name__}' has no attribute '{name}'")

    def clear_cache(self) -> None:
        cache = self._get_cache()
        cache.clear()

    def set_url(self, url: str) -> None:
        if not url:
            raise ValueError("url must be a non-empty string")
        self._custom_url = url
        self.clear_cache()
        self._cache = None

    def set_cache_dir(self, cache_dir: str) -> None:
        if not cache_dir:
            raise ValueError("cache_dir must be a non-empty string")
        self._custom_cache_dir = Path(cache_dir)
        if self._cache is not None:
            self._cache.close()
            self._cache = None


def make_module_api(loader_cls: type) -> dict:
    loader = loader_cls()
    return {
        "__getattr__": lambda name: loader.get_attr(name, loader_cls.__module__),
        "clear_cache": loader.clear_cache,
        "set_url": loader.set_url,
        "set_cache_dir": loader.set_cache_dir,
    }
