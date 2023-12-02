from dataclasses import dataclass
from typing import List

from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqStatusExistenceIssue(SigmaValidationIssue):
    description = "Rule has no status"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqStatusExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a status."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status is None:
            return [SigmahqStatusExistenceIssue([rule])]
        else:
            return []


@dataclass
class SigmahqStatusUnsupportedIssue(SigmaValidationIssue):
    description = "Rule has a UNSUPPORTED status"
    severity = SigmaValidationIssueSeverity.HIGH


class SigmahqStatusUnsupportedValidator(SigmaRuleValidator):
    """Checks if rule has a status UNSUPPORTED."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status and rule.status.name == "UNSUPPORTED":
            return [SigmahqStatusUnsupportedIssue([rule])]
        else:
            return []


@dataclass
class SigmahqStatusDeprecatedIssue(SigmaValidationIssue):
    description = "Rule has a DEPRECATED status"
    severity = SigmaValidationIssueSeverity.HIGH


class SigmahqStatusDeprecatedValidator(SigmaRuleValidator):
    """Checks if rule has a status DEPRECATED."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status and rule.status.name == "DEPRECATED":
            return [SigmahqStatusDeprecatedIssue([rule])]
        else:
            return []


@dataclass
class SigmahqDateExistenceIssue(SigmaValidationIssue):
    description = "Rule has no date"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqDateExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a data."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.date is None:
            return [SigmahqDateExistenceIssue([rule])]
        else:
            return []


@dataclass
class SigmahqDescriptionExistenceIssue(SigmaValidationIssue):
    description = "Rule has no description"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqDescriptionExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a description."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description is None:
            return [SigmahqDescriptionExistenceIssue([rule])]
        else:
            return []


@dataclass
class SigmahqDescriptionLengthIssue(SigmaValidationIssue):
    description = "Rule has a too short description"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqDescriptionLengthValidator(SigmaRuleValidator):
    """Checks if rule has a description."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description is not None and len(rule.description) < 16:
            return [SigmahqDescriptionLengthIssue([rule])]
        else:
            return []


@dataclass
class SigmahqLevelExistenceIssue(SigmaValidationIssue):
    description = "Rule has no level"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqLevelExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a level."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.level is None:
            return [SigmahqLevelExistenceIssue([rule])]
        else:
            return []
