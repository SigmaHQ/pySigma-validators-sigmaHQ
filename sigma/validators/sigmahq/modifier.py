from dataclasses import dataclass
from typing import ClassVar, List

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.validators.base import (
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
    SigmaDetectionItemValidator,
    SigmaDetectionItem,
)

from sigma.modifiers import (
    SigmaAllModifier,
    SigmaBase64Modifier,
    SigmaBase64OffsetModifier,
    SigmaRegularExpressionDotAllFlagModifier,
    SigmaRegularExpressionFlagModifier,
    SigmaRegularExpressionIgnoreCaseFlagModifier,
    SigmaRegularExpressionModifier,
    SigmaRegularExpressionMultilineFlagModifier,
    SigmaCaseSensitiveModifier,
)

@dataclass
class SigmahqFieldDuplicateValueIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Field list value has a duplicate item"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str
    value: str


class SigmahqFieldDuplicateValueValidator(SigmaDetectionItemValidator):
    """Check unique values in field lists."""

    CaseSensitiveModifierList = [
        SigmaBase64Modifier,
        SigmaBase64OffsetModifier,
        SigmaRegularExpressionDotAllFlagModifier,
        SigmaRegularExpressionFlagModifier,
        SigmaRegularExpressionIgnoreCaseFlagModifier,
        SigmaRegularExpressionModifier,
        SigmaRegularExpressionMultilineFlagModifier,
        SigmaCaseSensitiveModifier,
    ]

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []
        return super().validate(rule)

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        # Special case where value is case sensitive
        list_issue = []
        if any(modifier in detection_item.modifiers for modifier in self.CaseSensitiveModifierList):
            value_seen = []
            for v in detection_item.value:
                if v in value_seen:
                    if detection_item.field is not None:
                        list_issue.append(
                            SigmahqFieldDuplicateValueIssue(
                                [self.rule], detection_item.field, str(v)
                            )
                        )
                else:
                    value_seen.append(v)
        else:
            value_seen = []
            for v in detection_item.value:
                if str(v).lower() in value_seen:
                    if detection_item.field is not None:
                        list_issue.append(
                            SigmahqFieldDuplicateValueIssue(
                                [self.rule], detection_item.field, str(v)
                            )
                        )
                else:
                    value_seen.append(str(v).lower())
        return list_issue


@dataclass
class SigmahqInvalidAllModifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = "All modifier without a list of values"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqInvalidAllModifierValidator(SigmaDetectionItemValidator):
    """Check All modifier used with a single value."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []
        return super().validate(rule)

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if (
            SigmaAllModifier in detection_item.modifiers
            and len(detection_item.value) < 2
            and detection_item.field is not None
        ):
            return [SigmahqInvalidAllModifierIssue([self.rule], detection_item.field)]
        return []
