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

# Useless with Specification V2 
# @dataclass
# class SigmahqLogsourceCoherentIssue(SigmaValidationIssue):
#     description: ClassVar[str] = "Rule has an incoherent logsource"
#     severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
#     logsource: SigmaLogSource


# class SigmahqLogsourceCoherentValidator(SigmaRuleValidator):
#     """Checks if rule has Coherent logsource."""

#     def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
#         if rule.logsource.service and not rule.logsource.product:
#             return [SigmahqLogsourceCoherentIssue(rule, rule.logsource)]
#         else:
#             return []

@dataclass
class SigmahqLogsourceInvalidFieldIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has an invalid logsource field name"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    logsource: SigmaLogSource


class SigmahqLogsourceInvalidFielValidator(SigmaRuleValidator):
    """Checks if rule has an invalid logsource field name."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.logsource.custom_attributes:
            return [SigmahqLogsourceInvalidFieldIssue(rule, k ) for k in rule.logsource.custom_attributes.keys() if not k == "definition"]
        else:
            return []
