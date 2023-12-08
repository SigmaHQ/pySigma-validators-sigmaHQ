import json
from pathlib import Path
from dataclasses import dataclass
from typing import ClassVar, Dict, List

from sigma.rule import SigmaRule, SigmaLogSource
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

sigmahq_logsource_list: Dict[SigmaLogSource, str] = {}


@dataclass
class SigmahqLogsourceValidIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has an invalid logsource"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    logsource: SigmaLogSource


class SigmahqLogsourceValidValidator(SigmaRuleValidator):
    """Checks if rule has valid logsource."""

    def __init__(self):
        if Path("./tests/sigmahq_logsource_valid.json").exists():
            path_json = Path("./tests/sigmahq_logsource_valid.json")
        else:
            path_json = Path(__file__).parent.resolve() / Path(
                "data/sigmahq_logsource_valid.json"
            )

        with path_json.open("r") as file:
            logdata = json.load(file)
            for logsource in logdata["logsource"]:
                category = (
                    logsource["category"] if logsource["category"] != "" else None
                )
                product = logsource["product"] if logsource["product"] != "" else None
                service = logsource["service"] if logsource["service"] != "" else None
                sigmahq_logsource_list[SigmaLogSource(category, product, service)] = ""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.logsource and not rule.logsource in sigmahq_logsource_list:
            return [SigmahqLogsourceValidIssue(rule, rule.logsource)]
        else:
            return []
