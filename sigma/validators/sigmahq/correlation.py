from dataclasses import dataclass
from typing import ClassVar, List

from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType
from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

MIN_CORRELATION_RULES = 2

_TEMPORAL_TYPES = frozenset({SigmaCorrelationType.TEMPORAL, SigmaCorrelationType.TEMPORAL_ORDERED})
_GROUP_BY_REQUIRED_TYPES = frozenset(
    {
        SigmaCorrelationType.EVENT_COUNT,
        SigmaCorrelationType.VALUE_COUNT,
        SigmaCorrelationType.TEMPORAL,
        SigmaCorrelationType.TEMPORAL_ORDERED,
    }
)


@dataclass
class SigmahqCorrelationRulesMinimumIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Correlation rule must reference at least 2 rules for temporal types"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqCorrelationRulesMinimumValidator(SigmaRuleValidator):
    """Checks if temporal correlation rules have at least 2 rules."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            if rule.type in _TEMPORAL_TYPES:
                if len(rule.rules) < MIN_CORRELATION_RULES:  # type: ignore[arg-type]
                    return [SigmahqCorrelationRulesMinimumIssue([rule])]
        return []


@dataclass
class SigmahqCorrelationGroupByExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Correlation rule is missing the group-by field in correlation section"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqCorrelationGroupByExistenceValidator(SigmaRuleValidator):
    """Checks if a correlation rule has a group-by field for types that require it."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            if rule.type in _GROUP_BY_REQUIRED_TYPES:
                if rule.group_by is None or len(rule.group_by) == 0:
                    return [SigmahqCorrelationGroupByExistenceIssue([rule])]
        return []
