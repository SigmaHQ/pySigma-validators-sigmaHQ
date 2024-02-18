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
class SigmahqLogsourceValidIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has an invalid logsource"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    logsource: SigmaLogSource


class SigmahqLogsourceValidValidator(SigmaRuleValidator):
    """Checks if rule has valid logsource."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.logsource and not rule.logsource in config.sigmahq_logsource_list:
            return [SigmahqLogsourceValidIssue(rule, rule.logsource)]
        else:
            return []
