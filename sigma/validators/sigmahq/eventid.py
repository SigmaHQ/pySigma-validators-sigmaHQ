from dataclasses import dataclass
from typing import ClassVar, List

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


PROCESS_CREATION_PROVIDERS = (
    "Microsoft-Windows-Security-Auditing",
    "Microsoft-Windows-Sysmon",
)
MIGRATION_EVENT_IDS = (1, 4688)


@dataclass
class SigmahqEventIdProcessCreationIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses EventID 1 or 4688 with Provider_Name. "
        "Please migrate to the process_creation category."
    )
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


class SigmahqEventIdProcessCreationValidator(SigmaRuleValidator):
    """Checks if a rule uses EventID 1 or 4688 with Provider_Name instead of process_creation category."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []

        for detection in rule.detection.detections.values():
            for item in _iter_detection_items(detection):
                if item.field is not None and item.field.lower() == "provider_name":
                    for value in item.value:
                        value_str = str(value)
                        for provider in PROCESS_CREATION_PROVIDERS:
                            if provider in value_str:
                                return [SigmahqEventIdProcessCreationIssue([rule])]
        return []
