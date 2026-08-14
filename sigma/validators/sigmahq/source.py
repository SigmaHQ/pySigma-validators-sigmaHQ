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
class SigmahqSourceEventlogIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Detection contains 'Source: Eventlog' which does not add value."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


def _iter_detection_items(detection) -> List[SigmaDetectionItem]:
    """Recursively yield all SigmaDetectionItem objects from a detection tree."""
    items = []
    for item in detection.detection_items:
        if isinstance(item, SigmaDetectionItem):
            items.append(item)
        elif isinstance(item, SigmaDetection):
            items.extend(_iter_detection_items(item))
    return items


class SigmahqSourceEventlogValidator(SigmaRuleValidator):
    """Checks if a detection contains 'Source: Eventlog' which is redundant."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []

        for detection in rule.detection.detections.values():
            for item in _iter_detection_items(detection):
                if item.field is not None and item.field.lower() == "source":
                    for value in item.value:
                        if str(value).lower() == "eventlog":
                            return [SigmahqSourceEventlogIssue([rule])]
        return []
