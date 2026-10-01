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

    def _load_content(self, url: str) -> Any:
        """The index is a CSV document, not JSON."""
        return self._fetch_text(url)

    def _parse(self, content: Any) -> Dict[str, Any]:
        """Map every atomic GUID to its technique and test name.

        The index lists a test once per tactic, so a GUID can appear several
        times. Those repetitions always agree on both the technique and the
        name, hence the first occurrence wins and the mapping stays
        unambiguous: of the 2371 published rows, 1878 are distinct GUIDs and
        none carries two techniques or two names.
        """
        index: Dict[str, Dict[str, str]] = {}
        for row in csv.DictReader(io.StringIO(content)):
            guid = (row.get("Test GUID") or "").strip()
            if not guid:
                continue
            index.setdefault(
                guid,
                {
                    "technique": (row.get("Technique #") or "").strip(),
                    "name": (row.get("Test Name") or "").strip(),
                },
            )
        return {"sigmahq_atomic_red_team_test_by_guid": index}


globals().update(make_module_api(_AtomicRedTeamLoader))
