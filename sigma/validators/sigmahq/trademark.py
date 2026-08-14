from dataclasses import dataclass
from typing import ClassVar, List

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


TRADEMARKS = ("MITRE ATT&CK", "ATT&CK")


@dataclass
class SigmahqTrademarkIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule title contains a trademark violation."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    trademark: str


class SigmahqTrademarkValidator(SigmaRuleValidator):
    """Checks if a rule title contains trademarked terms that should not be used."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not isinstance(rule, SigmaRule):
            return []

        issues: List[SigmaValidationIssue] = []
        for trademark in TRADEMARKS:
            if trademark in rule.title:
                issues.append(SigmahqTrademarkIssue([rule], trademark))
        return issues
