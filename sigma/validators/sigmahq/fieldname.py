import re
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional, Tuple

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.types import SigmaString
from sigma.validators.base import (
    SigmaDetectionItem,
    SigmaDetectionItemValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

from sigma.validators.sigmahq.data import data_taxonomy


@dataclass
class SigmahqSpaceFieldNameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule uses a field name with a space instead of a underscore."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqSpaceFieldNameValidator(SigmaDetectionItemValidator):
    """Check if rules uses a field name that contains a space instead of an underscore."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not isinstance(rule, SigmaRule):
            return []
        return super().validate(rule)

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

    fields: Tuple[str, ...] = ()

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        self.fields = ()
        if not isinstance(rule, SigmaRule):
            return []

        logsource = getattr(rule, "logsource")

        logsource_key = f"{logsource.product}_{logsource.category}_{logsource.service}"
        if (
            logsource_key in data_taxonomy.sigmahq_taxonomy_fieldsname
            and len(data_taxonomy.sigmahq_taxonomy_fieldsname[logsource_key]) > 0
        ):
            self.fields = tuple(data_taxonomy.sigmahq_taxonomy_fieldsname[logsource_key])
            return super().validate(rule)

        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if (
            detection_item.field is not None
            and detection_item.field not in self.fields
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

    fields: Tuple[str, ...] = ()

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        self.fields = ()
        if not isinstance(rule, SigmaRule):
            return []

        logsource = getattr(rule, "logsource")

        logsource_key = f"{logsource.product}_{logsource.category}_{logsource.service}"
        if (
            logsource_key in data_taxonomy.sigmahq_taxonomy_fieldsname
            and len(data_taxonomy.sigmahq_taxonomy_fieldsname[logsource_key]) > 0
        ):
            self.fields = tuple(data_taxonomy.sigmahq_taxonomy_fieldsname[logsource_key])
            return super().validate(rule)

        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field is not None and detection_item.field not in self.fields:
            return [SigmahqInvalidFieldnameIssue([self.rule], detection_item.field)]
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

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not isinstance(rule, SigmaRule):
            return []
        return super().validate(rule)

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
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


@dataclass
class SigmahqInvalidHashKvIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A Sysmon Hash search must be valid Hash_Type=Hash_Value"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    value: str


class SigmahqInvalidHashKvValidator(SigmaDetectionItemValidator):
    """Check field Sysmon Hash Key-Value search is valid."""

    hash_field: Tuple[str, ...] = ("Hashes", "Hash")
    hash_key: Tuple[str, ...] = ("MD5", "SHA1", "SHA256", "IMPHASH")
    hash_regex: ClassVar[Dict[str, str]] = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA1": r"^[a-fA-F0-9]{40}$",
        "SHA256": r"^[a-fA-F0-9]{64}$",
        "IMPHASH": r"^[a-fA-F0-9]{32}$",
    }

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not isinstance(rule, SigmaRule):
            return []
        return super().validate(rule)

    def _hash_error(self, s_value: str) -> Optional[str]:
        """Return the invalid part of a Hash_Type=Hash_Value search, None if valid."""
        try:
            hash_name, hash_data = s_value.split("=")
        except ValueError:
            return s_value
        if hash_name not in self.hash_key:
            return hash_name
        if re.search(self.hash_regex[hash_name], hash_data) is None:
            return hash_data
        return None

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:

        errors = []
        if detection_item.field is not None and detection_item.field in self.hash_field:
            for v in detection_item.value:
                if isinstance(v, SigmaString):
                    for s_value in v.s:
                        if isinstance(s_value, str):
                            error = self._hash_error(s_value)
                            if error is not None:
                                errors.append(error)
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

    fields: Tuple[str, ...] = ()

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        self.fields = ()
        if not isinstance(rule, SigmaRule):
            return []

        logsource = getattr(rule, "logsource")

        logsource_key = f"{logsource.product}_{logsource.category}_{logsource.service}"
        if (
            logsource_key in data_taxonomy.sigmahq_taxonomy_redundant_fields
            and len(data_taxonomy.sigmahq_taxonomy_redundant_fields[logsource_key]) > 0
        ):
            self.fields = tuple(data_taxonomy.sigmahq_taxonomy_redundant_fields[logsource_key])
            return super().validate(rule)
        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:

        if detection_item.field is not None and detection_item.field in self.fields:
            return [SigmahqRedundantFieldIssue([self.rule], detection_item.field)]
        else:
            return []
