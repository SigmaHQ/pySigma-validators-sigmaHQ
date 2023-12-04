import re
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

sigmahq_logsource_prefix: Dict[SigmaLogSource, str] = {}
sigmahq_product_prefix: Dict[str, str] = {}


@dataclass
class SigmahqFilenameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filemane doesn't match SigmaHQ standard"
    severity: ClassVar[
        SigmaValidationIssueSeverity
    ] = SigmaValidationIssueSeverity.MEDIUM
    filename: str


class SigmahqFilenameValidator(SigmaRuleValidator):
    """Check rule filename match SigmaHQ standard."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        filename_pattern = re.compile(r"[a-z0-9_]{10,90}\.yml")
        if rule.source is not None:
            filename = rule.source.path.name
            if filename_pattern.match(filename) is None or not "_" in filename:
                return [SigmahqFilenameIssue(rule, filename)]
        return []


@dataclass
class SigmahqFilenamePrefixIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filemane doesn't match SigmaHQ Prefix standard"
    severity: ClassVar[
        SigmaValidationIssueSeverity
    ] = SigmaValidationIssueSeverity.MEDIUM
    filename: str
    logsource: SigmaLogSource
    prefix: str


class SigmahqFilenamePrefixValidator(SigmaRuleValidator):
    """Check rule filename match SigmaHQ prefix standard."""

    def __init__(self):
        if Path("./tests/sigmahq_logsource_prefix.json").exists():
            path_json = Path("./tests/sigmahq_logsource_prefix.json")
        else:
            path_json = Path(__file__).parent.resolve() / Path(
                "data/sigmahq_logsource_prefix.json"
            )

        with path_json.open("r") as file:
            logdata = json.load(file)
            for logsource in logdata.values():
                prefix = logsource["prefix"]
                category = (
                    logsource["category"] if logsource["category"] != "" else None
                )
                product = logsource["product"] if logsource["product"] != "" else None
                service = logsource["service"] if logsource["service"] != "" else None
                sigmahq_logsource_prefix[
                    SigmaLogSource(category, product, service)
                ] = prefix

        if Path("./tests/sigmahq_product_prefix.json").exists():
            path_json = Path("./tests/sigmahq_product_prefix.json")
        else:
            path_json = Path(__file__).parent.resolve() / Path(
                "data/sigmahq_product_prefix.json"
            )

        with path_json.open("r") as file:
            logdata = json.load(file)
            for product, prefix in logdata.items():
                sigmahq_product_prefix[product] = prefix

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.source is not None:
            filename = rule.source.path.name
            logsource = rule.logsource

            if logsource in sigmahq_logsource_prefix:
                if not filename.startswith(sigmahq_logsource_prefix[logsource]):
                    return [
                        SigmahqFilenamePrefixIssue(
                            rule,
                            filename,
                            logsource,
                            sigmahq_logsource_prefix[logsource],
                        )
                    ]
            else:
                if (
                    logsource.product in sigmahq_product_prefix
                    and not filename.startswith(
                        sigmahq_product_prefix[logsource.product]
                    )
                ):
                    return [
                        SigmahqFilenamePrefixIssue(
                            rule,
                            filename,
                            logsource,
                            sigmahq_product_prefix[logsource.product],
                        )
                    ]
        return []
