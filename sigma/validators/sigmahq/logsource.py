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
