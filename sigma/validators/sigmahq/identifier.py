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
class SigmahqIdentifierExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule is missing the id field"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqIdentifierExistenceValidator(SigmaRuleValidator):
    """Checks if a SigmaRule is missing the id field (mandatory for rules, optional for correlation rules)."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaRule) and rule.id is None:
            return [SigmahqIdentifierExistenceIssue([rule])]
        return []


@dataclass
class SigmahqIdentifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule id is not a valid UUID v4"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    id: str


class SigmahqIdentifierValidator(SigmaRuleValidator):
    """Checks if a rule id is a valid UUID v4 (RFC 4122 / RFC 9562)."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.id is not None and rule.id.version != 4:
            return [SigmahqIdentifierIssue([rule], str(rule.id))]
        return []
