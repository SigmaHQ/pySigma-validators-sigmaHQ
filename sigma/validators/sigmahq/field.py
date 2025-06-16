from pathlib import Path
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Tuple
import re

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
class SigmahqSpaceFieldNameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule uses a field name with a space instead of a underscore."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqSpaceFieldNameValidator(SigmaDetectionItemValidator):
    """Check if rules uses a field name that contains a space instead of an underscore."""

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field and " " in detection_item.field:
            return [SigmahqSpaceFieldNameIssue([self.rule], detection_item.field)]
        else:
            return []


@dataclass
class SigmahqFieldnameCastIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A field name have a cast error"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqFieldnameCastValidator(SigmaDetectionItemValidator):
    """Check field name have a cast error."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
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
        if (
            detection_item.field is not None
            and not detection_item.field in self.fields
            and any(x for x in self.fields if detection_item.field.casefold() == x.casefold())
        ):
            return [SigmahqFieldnameCastIssue([self.rule], detection_item.field)]
        else:
            return []


@dataclass
class SigmahqInvalidFieldnameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A field name do not exist"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqInvalidFieldnameValidator(SigmaDetectionItemValidator):
    """Check field name do not exist in the logsource."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
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


@dataclass
class SigmahqFieldUserIssue(SigmaValidationIssue):
    description: ClassVar[str] = "User Field has a Localized name"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str
    user: str


class SigmahqFieldUserValidator(SigmaDetectionItemValidator):
    """Check a User field use a localized name."""

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        # Special case where value is case sensitive
        if (
            detection_item.field
            and "user" in detection_item.field.lower()
            and len(detection_item.value) == 1
        ):
            user = str(detection_item.value[0])
            if "AUTORI" in user or "AUTHORI" in user:
                return [SigmahqFieldUserIssue([self.rule], detection_item.field, user)]
            else:
                return []
        else:
            return []


# Python 3.9 do not have the match
@dataclass
class SigmahqInvalidHashKvIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A Sysmon Hash search must be valid Hash_Type=Hash_Value"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    value: str


class SigmahqInvalidHashKvValidator(SigmaDetectionItemValidator):
    """Check field Sysmon Hash Key-Value search is valid."""

    hash_field: Tuple[str, ...] = ("Hashes", "Hash")
    hash_key: Tuple[str, ...] = ("MD5", "SHA1", "SHA256", "IMPHASH")

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:

        errors = []
        if detection_item.field is not None and detection_item.field in self.hash_field:
            for v in detection_item.value:
                if isinstance(v, SigmaString):
                    # v.original is empty when use |contains
                    for s_value in v.s:
                        if isinstance(s_value, str):
                            try:
                                hash_name, hash_data = s_value.split("=")
                                if hash_name in self.hash_key:
                                    # Initialize hash_regex with a default value
                                    hash_regex = r"^[a-fA-F0-9]{32}$"

                                    if hash_name == "MD5":
                                        hash_regex = r"^[a-fA-F0-9]{32}$"
                                    elif hash_name == "SHA1":
                                        hash_regex = r"^[a-fA-F0-9]{40}$"
                                    elif hash_name == "SHA256":
                                        hash_regex = r"^[a-fA-F0-9]{64}$"
                                    elif hash_name == "IMPHASH":
                                        hash_regex = r"^[a-fA-F0-9]{32}$"

                                    if re.search(hash_regex, hash_data) is None:
                                        errors.append(hash_data)
                                else:
                                    errors.append(hash_name)
                            except ValueError:
                                errors.append(s_value)
                else:
                    errors.append(v)

        return [SigmahqInvalidHashKvIssue([self.rule], v) for v in errors]


@dataclass
class SigmahqRedundantFieldIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A field name is redundant (already covered by the logsource)"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqRedundantFieldValidator(SigmaDetectionItemValidator):
    """Check if a field name is already covered by the logsource."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        core_logsource = SigmaLogSource(
            category=rule.logsource.category,
            product=rule.logsource.product,
            service=rule.logsource.service,
        )
        if (
            core_logsource in config.sigmahq_redundant_fields
            and len(config.sigmahq_redundant_fields[core_logsource]) > 0
        ):
            self.fields = config.sigmahq_redundant_fields[core_logsource]
            return super().validate(rule)
        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:

        if detection_item.field is not None and detection_item.field in self.fields:
            return [SigmahqRedundantFieldIssue([self.rule], detection_item.field)]
        else:
            return []
