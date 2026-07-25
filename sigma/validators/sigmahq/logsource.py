from dataclasses import dataclass
from typing import ClassVar, List

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaLogSource, SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

from sigma.validators.sigmahq.data import data_taxonomy


@dataclass
class SigmahqLogsourceUnknownIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule uses an unknown logsource"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    logsource: SigmaLogSource


class SigmahqLogsourceUnknownValidator(SigmaRuleValidator):
    """Checks if a rule uses an unknown logsource.

    This validator verifies that all logsource keys (product_category_service)
    are registered in the data taxonomy. If not, it raises a HIGH severity validation issue.
    """

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not isinstance(rule, SigmaRule):
            return []

        logsource = getattr(rule, "logsource")

        logsource_key = f"{logsource.product}_{logsource.category}_{logsource.service}"
        if logsource_key not in data_taxonomy.sigmahq_taxonomy_fieldsname:
            return [SigmahqLogsourceUnknownIssue([rule], logsource)]
        return []


@dataclass
class SigmahqSysmonMissingEventidIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses the windows sysmon service logsource without the EventID field"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqSysmonMissingEventidValidator(SigmaRuleValidator):
    """Checks if a rule using Sysmon logsource is missing the EventID field.

    This validator ensures that all rules using Windows Sysmon logsource have at least one
    detection item with the EventID field, which is required for proper event filtering.
    """

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not isinstance(rule, SigmaRule):
            return []

        if rule.logsource.service != "sysmon":
            return []

        has_eventid = any(
            item.field == "EventID"
            for selection in rule.detection.detections.values()
            for item in selection.detection_items
        )

        if not has_eventid:
            return [SigmahqSysmonMissingEventidIssue([rule])]
        return []
