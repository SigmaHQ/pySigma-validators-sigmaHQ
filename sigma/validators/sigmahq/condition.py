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
    description: ClassVar[str] = "Rule contains ' of them' with only 1 selection"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW


class SigmahqOfthemConditionValidator(SigmaRuleValidator):
    """Check use ' of them' with only one selection"""

    re_all_of_them: ClassVar[Pattern] = re.compile("\\s+of\\s+them")

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        if (
            any(
                [
                    self.re_all_of_them.search(condition)
                    for condition in rule.detection.condition
                ]
            )
            and len(rule.detection.detections) == 1
        ):
            return [SigmahqOfthemConditionIssue(rule)]
        else:
            return []


@dataclass
class SigmahqOfselectionConditionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule contains 'All/X of ' with only 1 selection"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    selection: str


class SigmahqOfselectionConditionValidator(SigmaRuleValidator):
    """Check use 'All/X of ' with only one selection"""

    re_x_of_them: ClassVar[Pattern] = re.compile("[\\d+|all]\\s+of\\s+([^\\s]+)")

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        for condition in rule.detection.condition:
            if self.re_x_of_them.search(condition):
                all_name = self.re_x_of_them.findall(condition)
                for name in all_name:

                    if name.startswith("filter_"):
                        continue

                    if name.endswith("*"):
                        selection_count = 0
                        for selection_name in rule.detection.detections:
                            if re.match(name, selection_name):
                                selection_count += 1
                        if selection_count < 2:
                            return [SigmahqOfselectionConditionIssue(rule, name)]
        return []


@dataclass
class SigmahqNoasterixofselectionConditionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule contains '1/all of ' without asterix"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )
    selection: str


class SigmahqNoasterixofselectionConditionValidator(SigmaRuleValidator):
    """Check use '1/all of ' without asterix"""

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
                        return [SigmahqNoasterixofselectionConditionIssue(rule, name)]
        return []
