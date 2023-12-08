import json
from pathlib import Path
from dataclasses import dataclass
from typing import ClassVar, Dict, List

from sigma.rule import SigmaRule, SigmaLogSource
from sigma.validators.base import (
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
    SigmaDetectionItemValidator,
    SigmaDetectionItem,
)

sigmahq_logsource_cast: Dict[SigmaLogSource, List[str]] = {}
sigmahq_logsource_unicast: Dict[SigmaLogSource, List[str]] = {}


def load_data_json(json_file: Path):
    with json_file.open("r") as file:
        logdata = json.load(file)
        for logsource in logdata.values():
            field = logsource["field"]
            category = logsource["category"] if logsource["category"] != "" else None
            product = logsource["product"] if logsource["product"] != "" else None
            service = logsource["service"] if logsource["service"] != "" else None
            sigmahq_logsource_cast[SigmaLogSource(category, product, service)] = field

            if "Hashes" in field or "Hash" in field:
                field.extend(["Imphash", "md5", "sha1", "sha256"])
            if product == "windows":
                field.extend(["EventID", "Provider_Name"])

            sigmahq_logsource_unicast[SigmaLogSource(category, product, service)] = [
                x.lower() for x in field
            ]


@dataclass
class SigmahqSpaceFieldnameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A field name have a space"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqSpaceFieldnameValidator(SigmaDetectionItemValidator):
    """Check field name have a space."""

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field and " " in detection_item.field:
            return [SigmahqSpaceFieldnameIssue(self.rule, detection_item.field)]
        else:
            return []


@dataclass
class SigmahqFieldnameCastIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A field name have a cast error"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqFieldnameCastValidator(SigmaDetectionItemValidator):
    """Check field name have a cast error."""

    def __init__(self):
        if sigmahq_logsource_cast == {}:
            if Path("./tests/sigmahq_product_cast.json").exists():
                path_json = Path("./tests/sigmahq_product_cast.json")
            else:
                path_json = Path(__file__).parent.resolve() / Path(
                    "data/sigmahq_product_cast.json"
                )
            load_data_json(path_json)

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.logsource in sigmahq_logsource_cast:
            self.fields = sigmahq_logsource_cast[rule.logsource]
            self.unifields = sigmahq_logsource_unicast[rule.logsource]
            return super().validate(rule)
        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if (
            detection_item.field is not None
            and detection_item.field.lower() in self.unifields
            and not detection_item.field in self.fields
        ):
            return [SigmahqFieldnameCastIssue(self.rule, detection_item.field)]
        else:
            return []


@dataclass
class SigmahqInvalidFieldnameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A field name do not exist"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str


class SigmahqInvalidFieldnameValidator(SigmaDetectionItemValidator):
    """Check field name do not exist in the logsource."""

    def __init__(self):
        if sigmahq_logsource_cast == {}:
            if Path("./tests/sigmahq_product_cast.json").exists():
                path_json = Path("./tests/sigmahq_product_cast.json")
            else:
                path_json = Path(__file__).parent.resolve() / Path(
                    "data/sigmahq_product_cast.json"
                )
            load_data_json(path_json)

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.logsource in sigmahq_logsource_cast:
            self.fields = sigmahq_logsource_cast[rule.logsource]
            self.unifields = sigmahq_logsource_unicast[rule.logsource]
            return super().validate(rule)
        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if (
            detection_item.field is not None
            and not detection_item.field.lower() in self.unifields
        ):
            return [SigmahqInvalidFieldnameIssue(self.rule, detection_item.field)]
        else:
            return []
