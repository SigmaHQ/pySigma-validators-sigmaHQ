from dataclasses import dataclass
from typing import ClassVar, List

from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaValidationIssue,
    SigmaRuleValidator,
    SigmaValidationIssueSeverity,
    SigmaDetectionItemValidator,
    SigmaDetectionItem,
)
from .config import ConfigHq

config = ConfigHq()


@dataclass
class SigmahqCategorieEventidIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule use a windows categorie that don't need EventId or Provider_Name"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqCategorieEventidValidator(SigmaDetectionItemValidator):
    """Checks if rule use Eventid with a windows category that allready include EventId or Provider_Name."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if (
            rule.logsource.product == "windows"
            and rule.logsource.category in ConfigHq.windows_categorie_no_eventid
        ):
            return super().validate(rule)
        else:
            return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field is not None and detection_item.field in [
            "EventID",
            "Provider_Name",
        ]:
            return [SigmahqCategorieEventidIssue(self.rule)]
        else:
            return []


@dataclass
class SigmahqSigmacIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule use a selection name that break sigmac"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )
    selection: str


class SigmahqSigmacValidator(SigmaRuleValidator):
    """Checks if rule use a selection name that break sigmac."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        for k in rule.detection.detections.keys():
            if k.startswith("or") or k.startswith("and") or k.startswith("not"):
                return [SigmahqSigmacIssue(rule, k)]
        return []
