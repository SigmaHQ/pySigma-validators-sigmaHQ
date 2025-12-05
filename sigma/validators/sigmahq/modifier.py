from pathlib import Path
from dataclasses import dataclass
from typing import ClassVar, List, Tuple
import re
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.types import SigmaString
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
from .config import ConfigHQ

config = ConfigHQ()


@dataclass
class SigmahqInvalidFieldnameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A field name do not exist"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqInvalidFieldnameValidator(SigmaDetectionItemValidator):
    """Check field name do not exist in the logsource."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []

        core_logsource = SigmaLogSource(
            category=rule.logsource.category,
            product=rule.logsource.product,
            service=rule.logsource.service,
        )
        if (
            core_logsource in config.sigma_fieldsname
            and len(config.sigma_fieldsname[core_logsource]) > 0
        ):
            self.fields = config.sigma_fieldsname[core_logsource]
            return super().validate(rule)

        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field is not None and not detection_item.field in self.fields:
            return [SigmahqInvalidFieldnameIssue([self.rule], detection_item.field)]
        else:
            return []


@dataclass
class SigmahqFieldDuplicateValueIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Field list value have a dulicate item"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str
    value: str


class SigmahqFieldDuplicateValueValidator(SigmaDetectionItemValidator):
    """Check uniques value in field list."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []
        return super().validate(rule)

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        # Special case where value is case sensitive
        if (
            SigmaBase64Modifier in detection_item.modifiers
            or SigmaBase64OffsetModifier in detection_item.modifiers
            or SigmaRegularExpressionDotAllFlagModifier in detection_item.modifiers
            or SigmaRegularExpressionFlagModifier in detection_item.modifiers
            or SigmaRegularExpressionIgnoreCaseFlagModifier in detection_item.modifiers
            or SigmaRegularExpressionModifier in detection_item.modifiers
            or SigmaRegularExpressionMultilineFlagModifier in detection_item.modifiers
            or SigmaCaseSensitiveModifier in detection_item.modifiers
        ):
            value_see = []
            for v in detection_item.value:
                if v in value_see:
                    if detection_item.field is not None:
                        return [
                            SigmahqFieldDuplicateValueIssue(
                                [self.rule], detection_item.field, str(v)
                            )
                        ]
                    else:
                        return []
                else:
                    value_see.append(v)
            return []
        else:
            value_see = []
            for v in detection_item.value:
                if str(v).lower() in value_see:
                    if detection_item.field is not None:
                        return [
                            SigmahqFieldDuplicateValueIssue(
                                [self.rule], detection_item.field, str(v)
                            )
                        ]
                    else:
                        return []
                else:
                    value_see.append(str(v).lower())
            return []


@dataclass
class SigmahqInvalidAllModifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = "All modifier without a list of value"
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
        if SigmaAllModifier in detection_item.modifiers and len(detection_item.value) < 2:
            if detection_item.field is not None:
                return [SigmahqInvalidAllModifierIssue([self.rule], detection_item.field)]
            else:
                return []
        else:
            return []
