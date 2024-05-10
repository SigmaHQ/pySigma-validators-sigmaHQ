from dataclasses import dataclass
from re import Pattern
import re
from typing import ClassVar, List, Set
from sigma.conditions import ConditionIdentifier, ConditionItem, ConditionSelector
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetections, SigmaRule
from sigma.validators.base import (
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
    SigmaRuleValidator,
)


@dataclass
class SigmahqOfthemConditionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule contains ' of them' with only 1 selection"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW


class SigmahqOfthemConditionValidator(SigmaRuleValidator):
    """Check use ' of them' with only one selection"""

    re_all_of_them: ClassVar[Pattern] = re.compile("\\s+of\\s+them")

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        if (
            any(
                [
                    self.re_all_of_them.search(condition)
                    for condition in rule.detection.condition
                ]
            )
            and len(rule.detection.detections) == 1
        ):
            return [SigmahqOfthemConditionIssue([rule])]
        else:
            return []
