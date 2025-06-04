from dataclasses import dataclass
from typing import ClassVar, Dict, List

from sigma.rule import SigmaRule, SigmaLogSource, SigmaRuleBase
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

from .config import ConfigHQ

config = ConfigHQ()


@dataclass
class SigmahqLogsourceUnknownIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule uses an unknown logsource"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    logsource: SigmaLogSource


class SigmahqLogsourceUnknownValidator(SigmaRuleValidator):
    """Checks if a rule uses an unknown logsource."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        # Ensure rule is a SigmaRule instance to access logsource
        logsource = getattr(rule, "logsource", None)
        if logsource is not None:
            core_logsource = SigmaLogSource(
                category=getattr(logsource, "category", None),
                product=getattr(logsource, "product", None),
                service=getattr(logsource, "service", None),
            )
            if not core_logsource in config.sigma_fieldsname:
                return [SigmahqLogsourceUnknownIssue([rule], logsource)]
            else:
                return []
        else:
            return []


@dataclass
class SigmahqSysmonMissingEventidIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses the windows sysmon service logsource without the EventID field"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqSysmonMissingEventidValidator(SigmaRuleValidator):
    """Checks if a rule uses the windows sysmon service logsource without the EventID field."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.logsource.service == "sysmon":
            find = False
            for selection in rule.detection.detections.values():
                for item in selection.detection_items:
                    if item.field == "EventID":
                        find = True
            if find:
                return []
            else:
                return [SigmahqSysmonMissingEventidIssue([rule])]
        else:
            return []
