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
class SigmahqRelatedIdentifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule related id is not a valid UUID v4"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    id: str


class SigmahqRelatedIdentifierValidator(SigmaRuleValidator):
    """Checks if a rule related ids are valid UUID v4 (RFC 4122 / RFC 9562)."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.related:
            issues = []
            for related_item in rule.related.related:
                if related_item.id.version != 4:
                    issues.append(SigmahqRelatedIdentifierIssue([rule], str(related_item.id)))
            return issues
        return []
