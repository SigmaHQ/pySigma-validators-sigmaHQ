from dataclasses import dataclass
from typing import ClassVar, List
from datetime import datetime

from sigma.rule import SigmaRule, SigmaStatus
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqStatusExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule is missing the status field"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqStatusExistenceValidator(SigmaRuleValidator):
    """Checks if a rule is missing the status field."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.status is None:
            return [SigmahqStatusExistenceIssue([rule])]
        else:
            return []


@dataclass
class SigmahqStatusIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses a status field with either Deprecated or Unsupported values, and it is not located in the appropriate folder."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqStatusValidator(SigmaRuleValidator):
    """Checks if a rule uses a status field with the value Deprecated or Unsupported, and its not located in the appropriate folder."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.status and rule.status.name in ["DEPRECATED", "UNSUPPORTED"]:
            return [SigmahqStatusIssue([rule])]
        else:
            return []


@dataclass
class SigmahqStatusToHighIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule has a status level that is too high for a newly created rule."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


@dataclass(frozen=True)
class SigmahqStatusToHighValidator(SigmaRuleValidator):
    """Checks if a new rule has a valid status regarding its age"""

    min_days_for_nolog_rule: int = 60
    min_days_for_log_rule: int = 0

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.date is None or rule.status is None:
            return []

        custom_keys = list(rule.custom_attributes.keys())
        max_status = (
            SigmaStatus.TEST if "regression_tests_path" in custom_keys else SigmaStatus.EXPERIMENTAL
        )
        min_days = (
            self.min_days_for_log_rule
            if "regression_tests_path" in custom_keys
            else self.min_days_for_nolog_rule
        )
        delta_days = (datetime.now().date() - rule.date).days

        if rule.status > max_status and delta_days <= min_days:
            return [SigmahqStatusToHighIssue([rule])]
        return []
