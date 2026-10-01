import re
import warnings
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, ClassVar, Dict, List
from uuid import UUID

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

from sigma.validators.sigmahq.data import data_atomic_red_team

_SIM_TYPE_EXPECTED = "atomic-red-team"
_SIM_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_REQUIRED_KEYS = {"type", "name", "technique", "atomic_guid"}
_ALLOWED_KEYS = _REQUIRED_KEYS
# Two test names that differ only by case or punctuation are treated as the same
# name, so only a real divergence between the rule and the index is reported.
_NAME_SIMILARITY_THRESHOLD = 0.8


@dataclass
class SigmahqSimulationNotListIssue(SigmaValidationIssue):
    description: ClassVar[str] = "simulation field must be a list"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


@dataclass
class SigmahqSimulationEmptyIssue(SigmaValidationIssue):
    description: ClassVar[str] = "simulation list must not be empty"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


@dataclass
class SigmahqSimulationEntryNotDictIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Each simulation entry must be a dictionary"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


@dataclass
class SigmahqSimulationMissingKeyIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Simulation entry is missing required keys"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    missing_keys: List[str]


@dataclass
class SigmahqSimulationUnknownKeyIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Simulation entry contains unknown keys"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    unknown_keys: List[str]


@dataclass
class SigmahqSimulationInvalidTypeIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid simulation type - must be 'atomic-red-team'"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    type_value: str


@dataclass
class SigmahqSimulationInvalidNameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Simulation name must be a non-empty string"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


@dataclass
class SigmahqSimulationInvalidTechniqueIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid MITRE ATT&CK technique format"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    technique: str


@dataclass
class SigmahqSimulationInvalidAtomicGuidIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid atomic GUID format"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    atomic_guid: str


class SigmahqSimulationValidator(SigmaRuleValidator):
    """Validates the simulation field structure and content."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not rule.custom_attributes:
            return []

        simulation = rule.custom_attributes.get("simulation")
        if simulation is None:
            return []

        if not isinstance(simulation, list):
            return [SigmahqSimulationNotListIssue([rule])]

        if not simulation:
            return [SigmahqSimulationEmptyIssue([rule])]

        issues: List[SigmaValidationIssue] = []
        for entry in simulation:
            if not isinstance(entry, dict):
                issues.append(SigmahqSimulationEntryNotDictIssue([rule]))
                continue
            issues.extend(self._validate_keys(rule, entry))
            issues.extend(self._validate_values(rule, entry))
        return issues

    def _validate_keys(
        self, rule: SigmaRule | SigmaCorrelationRule, entry: Dict[str, Any]
    ) -> List[SigmaValidationIssue]:
        """Check that the entry carries exactly the required keys.

        Value checks are skipped for keys reported as missing, so a missing key
        yields one issue instead of two.
        """
        issues: List[SigmaValidationIssue] = []
        entry_keys = set(entry.keys())

        missing = sorted(_REQUIRED_KEYS - entry_keys)
        if missing:
            issues.append(SigmahqSimulationMissingKeyIssue([rule], missing_keys=missing))
            entry_keys -= set(missing)

        unknown = sorted(entry_keys - _ALLOWED_KEYS)
        if unknown:
            issues.append(SigmahqSimulationUnknownKeyIssue([rule], unknown_keys=unknown))
        return issues

    def _validate_values(
        self, rule: SigmaRule | SigmaCorrelationRule, entry: Dict[str, Any]
    ) -> List[SigmaValidationIssue]:
        """Check each required key that is present in the entry."""
        issues: List[SigmaValidationIssue] = []

        if "type" in entry and entry["type"] != _SIM_TYPE_EXPECTED:
            issues.append(SigmahqSimulationInvalidTypeIssue([rule], type_value=str(entry["type"])))

        if "name" in entry and (not isinstance(entry["name"], str) or not entry["name"].strip()):
            issues.append(SigmahqSimulationInvalidNameIssue([rule]))

        if "technique" in entry and (
            not isinstance(entry["technique"], str) or not _SIM_TECH_RE.match(entry["technique"])
        ):
            issues.append(
                SigmahqSimulationInvalidTechniqueIssue([rule], technique=str(entry["technique"]))
            )

        if "atomic_guid" in entry and not self._is_uuid(entry["atomic_guid"]):
            issues.append(
                SigmahqSimulationInvalidAtomicGuidIssue(
                    [rule], atomic_guid=str(entry["atomic_guid"])
                )
            )
        return issues

    @staticmethod
    def _is_uuid(value: Any) -> bool:
        """A UUID is accepted as a string with or without dashes; other types are not."""
        if not isinstance(value, str):
            return False
        try:
            UUID(value)
        except ValueError:
            return False
        return True


@dataclass
class SigmahqSimulationUnknownAtomicTestIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "simulation references an atomic_guid that does not exist in the Atomic Red Team index"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    atomic_guid: str


def _known_test_names() -> Dict[str, str] | None:
    """Return the Atomic Red Team GUID to name mapping, or None if unavailable.

    The index lives outside this repository, so it can be unreachable because of
    a network outage, a rate limit or an upstream move. Validators depending on
    it must then stay silent instead of failing every rule: a false positive on
    every rule of the repository is worse than a skipped cross-check.
    """
    try:
        return data_atomic_red_team.sigmahq_atomic_red_team_test_name_by_guid
    except RuntimeError as e:
        warnings.warn(
            f"Atomic Red Team index unavailable, simulation cross-checks skipped: {e}",
            stacklevel=2,
        )
        return None


class SigmahqSimulationAtomicTestExistsValidator(SigmaRuleValidator):
    """Checks that every atomic_guid is present in the Atomic Red Team index."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        simulation = _simulation_entries(rule)
        if simulation is None:
            return []

        known = _known_test_names()
        if known is None:
            return []

        issues: List[SigmaValidationIssue] = []
        for entry in simulation:
            guid = entry.get("atomic_guid")
            if isinstance(guid, str) and guid not in known:
                issues.append(SigmahqSimulationUnknownAtomicTestIssue([rule], atomic_guid=guid))
        return issues


@dataclass
class SigmahqSimulationAtomicTestNameIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "simulation name does not match the name of the atomic test referenced by atomic_guid"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    name: str
    expected_name: str


@dataclass(frozen=True)
class SigmahqSimulationAtomicTestNameValidator(SigmaRuleValidator):
    """Checks that name matches the test the atomic_guid points to.

    The technique is deliberately not compared with the index: Atomic Red Team
    master renumbered several techniques (T1562.001 became T1685), and the
    references of a rule may legitimately keep the older identifier.

    Names that only differ by case or punctuation are accepted, since several
    existing rules spell a test slightly differently than the index does.
    """

    name_similarity_threshold: float = _NAME_SIMILARITY_THRESHOLD

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        simulation = _simulation_entries(rule)
        if simulation is None:
            return []

        known = _known_test_names()
        if known is None:
            return []

        issues: List[SigmaValidationIssue] = []
        for entry in simulation:
            guid = entry.get("atomic_guid")
            name = entry.get("name")
            if not isinstance(guid, str) or guid not in known:
                continue
            if not isinstance(name, str) or not name.strip():
                continue

            expected_name = known[guid]
            if _names_match(name, expected_name, self.name_similarity_threshold):
                continue
            issues.append(
                SigmahqSimulationAtomicTestNameIssue([rule], name=name, expected_name=expected_name)
            )
        return issues


def _simulation_entries(rule: SigmaRule | SigmaCorrelationRule) -> List[Dict[str, Any]] | None:
    """Return the well formed entries of the simulation field, or None if unusable.

    Entries are filtered so that the validators relying on the Atomic Red Team
    index only inspect dict entries with a string GUID, and never duplicate the
    structural findings of SigmahqSimulationValidator.
    """
    if not rule.custom_attributes:
        return None

    simulation = rule.custom_attributes.get("simulation")
    if not isinstance(simulation, list):
        return None

    return [
        entry
        for entry in simulation
        if isinstance(entry, dict) and isinstance(entry.get("atomic_guid"), str)
    ]


def _names_match(name: str, expected_name: str, threshold: float) -> bool:
    """Compare two test names, ignoring case and surrounding whitespace."""
    normalized = name.strip().casefold()
    normalized_expected = expected_name.strip().casefold()
    if normalized == normalized_expected:
        return True
    return SequenceMatcher(None, normalized, normalized_expected).ratio() >= threshold
