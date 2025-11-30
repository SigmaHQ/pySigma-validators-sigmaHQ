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
class SigmahqAuthorExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule is missing the author field"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqAuthorExistenceValidator(SigmaRuleValidator):
    """Checks if a rule is missing the author field."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.author is None:
            return [SigmahqAuthorExistenceIssue([rule])]
        else:
            return []
