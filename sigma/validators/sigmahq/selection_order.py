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
class SigmahqSelectionAlphabeticalOrderIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Selection list is not in alphabetical order."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    field: str
    selection: str
    values: List[str]


class SigmahqSelectionAlphabeticalOrderValidator(SigmaRuleValidator):
    """Checks if any multi-item selection list is sorted alphabetically."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []

        issues: List[SigmaValidationIssue] = []
        for sel_name, detection in rule.detection.detections.items():
            for item in detection.detection_items:
                if hasattr(item, "field") and item.field and hasattr(item, "value"):
                    if isinstance(item.value, list) and len(item.value) >= 2:
                        values = [str(v) for v in item.value]
                        if values != sorted(values):
                            issues.append(
                                SigmahqSelectionAlphabeticalOrderIssue(
                                    [rule], sel_name, item.field, values
                                )
                            )
        return issues
