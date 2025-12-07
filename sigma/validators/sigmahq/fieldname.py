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

from sigma.validators.sigmahq.data import data_taxonomy


@dataclass
class SigmahqSpaceFieldNameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule uses a field name with a space instead of a underscore."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqSpaceFieldNameValidator(SigmaDetectionItemValidator):
    """Check if rules uses a field name that contains a space instead of an underscore."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
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

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []

        # Sigma rule must have a log source
        logsource = getattr(rule, "logsource")

        logsource_key = f"{logsource.product}_{logsource.category}_{logsource.service}"
        if (
            logsource_key in data_taxonomy.sigmahq_taxonomy_fieldsname
            and len(data_taxonomy.sigmahq_taxonomy_fieldsname[logsource_key]) > 0
        ):
            self.fields = data_taxonomy.sigmahq_taxonomy_fieldsname[logsource_key]
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

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []

        # Sigma rule must have a log source
        logsource = getattr(rule, "logsource")

        logsource_key = f"{logsource.product}_{logsource.category}_{logsource.service}"
        if (
            logsource_key in data_taxonomy.sigmahq_taxonomy_fieldsname
            and len(data_taxonomy.sigmahq_taxonomy_fieldsname[logsource_key]) > 0
        ):
            self.fields = data_taxonomy.sigmahq_taxonomy_fieldsname[logsource_key]
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
class SigmahqFieldUserIssue(SigmaValidationIssue):
    description: ClassVar[str] = "User Field has a Localized name"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str
    user: str


class SigmahqFieldUserValidator(SigmaDetectionItemValidator):
    """Check a User field use a localized name."""

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

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []
        return super().validate(rule)

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

                                    match hash_name:
                                        case "MD5":
                                            hash_regex = r"^[a-fA-F0-9]{32}$"
                                        case "SHA1":
                                            hash_regex = r"^[a-fA-F0-9]{40}$"
                                        case "SHA256":
                                            hash_regex = r"^[a-fA-F0-9]{64}$"
                                        case "IMPHASH":
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

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []

        # Sigma rule must have a log source
        logsource = getattr(rule, "logsource")

        logsource_key = f"{logsource.product}_{logsource.category}_{logsource.service}"
        if (
            logsource_key in data_taxonomy.sigmahq_taxonomy_redundant_fields
            and len(data_taxonomy.sigmahq_taxonomy_redundant_fields[logsource_key]) > 0
        ):
            self.fields = data_taxonomy.sigmahq_taxonomy_redundant_fields[logsource_key]
            return super().validate(rule)
        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:

        if detection_item.field is not None and detection_item.field in self.fields:
            return [SigmahqRedundantFieldIssue([self.rule], detection_item.field)]
        else:
            return []
