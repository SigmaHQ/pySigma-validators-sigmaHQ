from dataclasses import dataclass
from typing import ClassVar, List

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqSelectionSingleValueIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Selection has a list with only 1 element."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    selection: str
    field: str


def _iter_detection_items(detection) -> List[SigmaDetectionItem]:
    """Recursively yield all SigmaDetectionItem objects from a detection tree."""
    items = []
    for item in detection.detection_items:
        if isinstance(item, SigmaDetectionItem):
            items.append(item)
        elif isinstance(item, SigmaDetection):
            items.extend(_iter_detection_items(item))
    return items


class SigmahqSelectionSingleValueValidator(SigmaRuleValidator):
    """Checks if any selection has a list with only 1 element."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []

        issues: List[SigmaValidationIssue] = []
        for sel_name, detection in rule.detection.detections.items():
            for item in _iter_detection_items(detection):
                if item.field is not None and len(item.value) == 1:
                    issues.append(SigmahqSelectionSingleValueIssue([rule], sel_name, item.field))
        return issues
