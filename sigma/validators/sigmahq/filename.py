import re
from dataclasses import dataclass
from typing import ClassVar, Dict, List

from sigma.rule import SigmaRule, SigmaLogSource

from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

from .config import ConfigHq

config = ConfigHq()


@dataclass
class SigmahqFilenameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filemane doesn't match SigmaHQ standard"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )
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
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )
    filename: str
    logsource: SigmaLogSource
    prefix: str


class SigmahqFilenamePrefixValidator(SigmaRuleValidator):
    """Check rule filename match SigmaHQ prefix standard."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.source is not None:
            filename = rule.source.path.name
            logsource = rule.logsource

            if logsource in config.sigmahq_logsource_prefix:
                if not filename.startswith(config.sigmahq_logsource_prefix[logsource]):
                    return [
                        SigmahqFilenamePrefixIssue(
                            rule,
                            filename,
                            logsource,
                            config.sigmahq_logsource_prefix[logsource],
                        )
                    ]
            else:
                if (
                    logsource.product in config.sigmahq_product_prefix
                    and not filename.startswith(
                        config.sigmahq_product_prefix[logsource.product]
                    )
                ):
                    return [
                        SigmahqFilenamePrefixIssue(
                            rule,
                            filename,
                            logsource,
                            config.sigmahq_product_prefix[logsource.product],
                        )
                    ]
        return []
