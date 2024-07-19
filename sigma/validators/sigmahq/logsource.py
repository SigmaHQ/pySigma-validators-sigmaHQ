from dataclasses import dataclass
from typing import ClassVar, Dict, List

from sigma.rule import SigmaRule, SigmaLogSource
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

from .config import ConfigHq

config = ConfigHq()


@dataclass
class SigmahqLogsourceKnownIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has an unknown logsource"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    logsource: SigmaLogSource


class SigmahqLogsourceKnownValidator(SigmaRuleValidator):
    """Checks if rule has known logsource."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if not rule.logsource in config.sigmahq_logsource_list:
            return [SigmahqLogsourceKnownIssue(rule, rule.logsource)]
        else:
            return []


@dataclass
class SigmahqSysmonMissingEventidIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule use windows sysmon service without EventID"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqSysmonMissingEventidValidator(SigmaRuleValidator):
    """Checks if rule use windows sysmon service without EventID."""

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
                return [SigmahqSysmonMissingEventidIssue(rule)]
        else:
            return []
