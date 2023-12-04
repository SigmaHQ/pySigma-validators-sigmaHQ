from dataclasses import dataclass
from typing import ClassVar, List

from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
    SigmaDetectionItemValidator,
    SigmaDetectionItem,
)


@dataclass
class SigmahqSpaceFieldnameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A field name have a space"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqSpaceFieldnameValidator(SigmaDetectionItemValidator):
    """Check field name have no space."""

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field and " " in detection_item.field:
            return [SigmahqSpaceFieldnameIssue(self.rule, detection_item.field)]
        else:
            return []
