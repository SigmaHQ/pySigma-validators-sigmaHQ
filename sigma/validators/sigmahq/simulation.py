import re
from dataclasses import dataclass
from typing import Any, ClassVar, Dict, List
from uuid import UUID

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

_SIM_TYPE_EXPECTED = "atomic-red-team"
_SIM_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_REQUIRED_KEYS = {"type", "name", "technique", "atomic_guid"}
_ALLOWED_KEYS = _REQUIRED_KEYS


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
