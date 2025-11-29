from dataclasses import dataclass
from typing import ClassVar, List, Tuple
import re

from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqLevelExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule is missing the level field"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqLevelExistenceValidator(SigmaRuleValidator):
    """Checks if a rule is missing the level field"""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.level is None:
            return [SigmahqLevelExistenceIssue([rule])]
        else:
            return []

