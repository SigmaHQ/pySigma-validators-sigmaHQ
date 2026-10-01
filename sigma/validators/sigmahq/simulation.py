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
        """Accept a UUIDv4 string, with or without dashes; other types are not.

        Every GUID published in the Atomic Red Team index is a version 4 UUID,
        so any other version cannot resolve to a test.
        """
        if not isinstance(value, str):
            return False
        try:
            parsed = UUID(value)
        except ValueError:
            return False
        return parsed.version == 4


@dataclass
class SigmahqSimulationUnknownAtomicTestIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "simulation references an atomic_guid that does not exist in the Atomic Red Team index"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    atomic_guid: str


def _known_tests() -> Dict[str, Dict[str, str]] | None:
    """Return the Atomic Red Team GUID to test mapping, or None if unavailable.

    The index lives outside this repository, so it can be unreachable because of
    a network outage, a rate limit or an upstream move. Validators depending on
    it must then stay silent instead of failing every rule: a false positive on
    every rule of the repository is worse than a skipped cross-check.
    """
    try:
        return data_atomic_red_team.sigmahq_atomic_red_team_test_by_guid
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

        known = _known_tests()
        if known is None:
            return []

        issues: List[SigmaValidationIssue] = []
        for entry in simulation:
            guid = entry.get("atomic_guid")
            if isinstance(guid, str) and guid not in known:
                issues.append(SigmahqSimulationUnknownAtomicTestIssue([rule], atomic_guid=guid))
        return issues


_ART_REFERENCE_RE = re.compile(
    r"redcanaryco/atomic-red-team/(?:blob|tree)/[0-9a-f]{40}/atomics/(T\d{4}(?:\.\d{3})?)/"
)


def _index_technique(guid: str) -> str | None:
    """Return the technique the index gives to a GUID, or None if unavailable."""
    known = _known_tests()
    if known is None or guid not in known:
        return None
    return known[guid]["technique"]


@dataclass
class SigmahqSimulationAtomicReferenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "simulation atomic_guid is not documented by any Atomic Red Team reference of the rule"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    atomic_guid: str


@dataclass
class SigmahqSimulationAtomicReferenceTechniqueIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Atomic Red Team reference of the rule does not point to the technique of the "
        "atomic test referenced by atomic_guid"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    link: str
    technique: str
    expected_technique: str


class SigmahqSimulationAtomicReferenceValidator(SigmaRuleValidator):
    """Checks that an Atomic Red Team reference documents the simulated test.

    A simulation claims that a rule was validated against one specific atomic
    test, so the rule must link that test. The reference is expected to be a
    permalink of the form
    https://github.com/redcanaryco/atomic-red-team/blob/<sha>/atomics/T1027.001/T1027.001.md
    whose path carries the technique of the test.

    Both the technique of the simulation and the technique of the index are
    accepted against that path, so only a genuine divergence is reported.
    """

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        simulation = _simulation_entries(rule)
        if simulation is None:
            return []

        links = [
            link
            for link in (rule.references or [])
            if isinstance(link, str) and "redcanaryco/atomic-red-team" in link
        ]
        if not links:
            return [
                SigmahqSimulationAtomicReferenceIssue([rule], atomic_guid=entry["atomic_guid"])
                for entry in simulation
            ]

        referenced_techniques = set()
        for link in links:
            match = _ART_REFERENCE_RE.search(link)
            if match is not None:
                referenced_techniques.add(match.group(1))

        issues: List[SigmaValidationIssue] = []
        for entry in simulation:
            guid = entry["atomic_guid"]
            technique = entry.get("technique")
            if not isinstance(technique, str) or not technique.strip():
                continue

            expected_technique = _index_technique(guid)
            candidates = [technique]
            if expected_technique is not None:
                candidates.append(expected_technique)
            if any(
                _techniques_match(referenced, candidate)
                for referenced in referenced_techniques
                for candidate in candidates
            ):
                continue

            issues.append(
                SigmahqSimulationAtomicReferenceTechniqueIssue(
                    [rule],
                    link=sorted(links)[0],
                    technique=technique,
                    expected_technique=expected_technique or technique,
                )
            )
        return issues


@dataclass
class SigmahqSimulationAtomicTestTechniqueIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "simulation technique does not match the technique of the atomic test "
        "referenced by atomic_guid"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    technique: str
    expected_technique: str


class SigmahqSimulationAtomicTestTechniqueValidator(SigmaRuleValidator):
    """Checks that technique matches the test the atomic_guid points to.

    A GUID identifies exactly one test in the index, and every one of the 1878
    published GUIDs carries a single technique, so the comparison is
    unambiguous.

    The technique is still compared with a lenient format: a rule may spell the
    parent technique T1059 where the index spells the sub-technique T1059.001,
    which is the same test and must not be reported.
    """

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        simulation = _simulation_entries(rule)
        if simulation is None:
            return []

        known = _known_tests()
        if known is None:
            return []

        issues: List[SigmaValidationIssue] = []
        for entry in simulation:
            guid = entry.get("atomic_guid")
            technique = entry.get("technique")
            if not isinstance(guid, str) or guid not in known:
                continue
            if not isinstance(technique, str) or not technique.strip():
                continue

            expected_technique = known[guid]["technique"]
            if _techniques_match(technique, expected_technique):
                continue
            issues.append(
                SigmahqSimulationAtomicTestTechniqueIssue(
                    [rule], technique=technique, expected_technique=expected_technique
                )
            )
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

    Names that only differ by case or punctuation are accepted, since a rule
    may legitimately spell a test slightly differently than the index does.
    """

    name_similarity_threshold: float = _NAME_SIMILARITY_THRESHOLD

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        simulation = _simulation_entries(rule)
        if simulation is None:
            return []

        known = _known_tests()
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

            expected_name = known[guid]["name"]
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


def _techniques_match(technique: str, expected_technique: str) -> bool:
    """Compare a technique with the one of the index, tolerating the parent form.

    A rule that spells the parent technique T1059 against an index entry of
    T1059.001 describes the same test, so only a real divergence is reported.
    """
    normalized = technique.strip().upper()
    normalized_expected = expected_technique.strip().upper()
    if normalized == normalized_expected:
        return True
    return normalized == normalized_expected.split(".")[0]
