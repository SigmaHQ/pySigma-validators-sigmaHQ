from dataclasses import dataclass
from typing import ClassVar, List

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqLicenseIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a malformed 'license' field (has to be a string)."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqLicenseValidator(SigmaRuleValidator):
    """Checks if a rule has a malformed 'license' field."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not isinstance(rule, SigmaRule):
            return []

        if rule.license is not None and not isinstance(rule.license, str):
            return [SigmahqLicenseIssue([rule])]
        return []
