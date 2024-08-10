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
from .config import ConfigHQ

config = ConfigHQ()


@dataclass
class SigmahqCategoryEventIdIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses a windows logsource category that doesn't require the use of an EventID field"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqCategoryEventIdValidator(SigmaDetectionItemValidator):
    """Checks if a rule uses an EventID field with a windows category logsource that doesn't require it."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if (
            rule.logsource.product == "windows"
            and rule.logsource.category in ConfigHQ.windows_category_no_eventid
        ):
            return super().validate(rule)
        else:
            return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field is not None and detection_item.field == "EventID":
            return [SigmahqCategoryEventIdIssue(self.rule)]
        else:
            return []


@dataclass
class SigmahqCategoriProvidernameIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses a windows logsource category that doesn't require the use of the Provider_Name field"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqCategoriProvidernameValidator(SigmaDetectionItemValidator):
    """Checks if a rule uses a Provider_Name field with a windows category logsource that doesn't require it."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if (
            rule.logsource.product == "windows"
            and rule.logsource.category in ConfigHQ.windows_category_provider_name
        ):
            return super().validate(rule)
        else:
            return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field is not None and detection_item.field == "Provider_Name":
            for v in detection_item.value:
                if (
                    v
                    in ConfigHQ.windows_category_provider_name[
                        self.rule.logsource.category
                    ]
                ):
                    return [SigmahqCategoriProvidernameIssue(self.rule)]

        return []
