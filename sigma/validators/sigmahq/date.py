from dataclasses import dataclass
from typing import ClassVar, List

from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqDateExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule is missing the date field"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqDateExistenceValidator(SigmaRuleValidator):
    """Checks if a rule is missing the date field."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.date is None:
            return [SigmahqDateExistenceIssue([rule])]
        else:
            return []


@dataclass
class SigmahqModifiedDateOrderIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule has a modified field whose value is older than that of the date field. The modified date has always to be newer than date."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqModifiedDateOrderValidator(SigmaRuleValidator):
    """Checks if a rule has a modified field that has value older than the date field."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.date is not None and rule.modified is not None:
            if rule.modified < rule.date:
                return [SigmahqModifiedDateOrderIssue([rule])]
        return []


@dataclass
class SigmahqModifiedWithoutDateIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule has a modified field without a date field. New rules should only have a date field."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqModifiedWithoutDateValidator(SigmaRuleValidator):
    """Checks if a rule has a modified field without a date field."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.modified is not None and rule.date is None:
            return [SigmahqModifiedWithoutDateIssue([rule])]
        return []


@dataclass
class SigmahqRedundantModifiedIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule has a redundant modified field and needs to be removed. (date == modified)"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqRedundantModifiedValidator(SigmaRuleValidator):
    """Checks if a rule has a redundant modified field"""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.date is not None and rule.modified is not None:
            if rule.date == rule.modified:
                return [SigmahqRedundantModifiedIssue([rule])]
        return []
