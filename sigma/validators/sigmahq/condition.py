from dataclasses import dataclass
from re import Pattern
import re
from typing import ClassVar, List, Set
from sigma.conditions import ConditionIdentifier, ConditionItem, ConditionSelector
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetections, SigmaRule
from sigma.validators.base import (
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
    SigmaRuleValidator,
)


@dataclass
class SigmahqOfthemConditionIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses the ' of them' keyword in the condition with only one selection in the detection section"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW


class SigmahqOfthemConditionValidator(SigmaRuleValidator):
    """Check use of the ' of them' keyword with only a single selection in the detection section"""

    re_all_of_them: ClassVar[Pattern] = re.compile("\\s+of\\s+them")

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        if (
            any([self.re_all_of_them.search(condition) for condition in rule.detection.condition])
            and len(rule.detection.detections) == 1
        ):
            return [SigmahqOfthemConditionIssue(rule)]
        else:
            return []


@dataclass
class SigmahqOfselectionConditionIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses the 'All/X of ' format in the condition with only one selection in the detection section"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    selection: str


class SigmahqOfselectionConditionValidator(SigmaRuleValidator):
    """Check use of the 'All/X of ' format with only one selection in the detection section"""

    re_x_of_them: ClassVar[Pattern] = re.compile("[\\d+|all]\\s+of\\s+([^\\s]+)")

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        for condition in rule.detection.condition:
            if self.re_x_of_them.search(condition):
                all_name = self.re_x_of_them.findall(condition)
                for name in all_name:
                    if name.startswith("filter_") and name.endswith("_*"):
                        continue

                    if name.startswith("selection_") and name.endswith("_*"):
                        continue

                    if name.endswith("_*"):
                        selection_count = 0
                        for selection_name in rule.detection.detections:
                            if re.match(name, selection_name):
                                selection_count += 1
                        if selection_count < 2:
                            return [SigmahqOfselectionConditionIssue(rule, name)]
        return []


@dataclass
class SigmahqMissingAsteriskConditionIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses a '1/all of ' keyword in the condition without an asterisk"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    selection: str


class SigmahqMissingAsteriskConditionValidator(SigmaRuleValidator):
    """Check the use of the '1/all of ' keyword without an asterisk in the condition"""

    re_x_of_them: ClassVar[Pattern] = re.compile("\\s+of\\s+([^\\s\\)]+)")

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        for condition in rule.detection.condition:
            if self.re_x_of_them.search(condition):
                all_name = self.re_x_of_them.findall(condition)
                for name in all_name:
                    if name == "them":
                        continue
                    if not name.endswith("*"):
                        return [SigmahqMissingAsteriskConditionIssue(rule, name)]
        return []
