import re
from dataclasses import dataclass
from typing import ClassVar, Dict, List

from sigma.rule import SigmaRule, SigmaLogSource

from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

from .config import ConfigHQ

config = ConfigHQ()


@dataclass
class SigmahqFilenameConventionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "The rule filename doesn't match SigmaHQ convention"
    severity: ClassVar[
        SigmaValidationIssueSeverity
    ] = SigmaValidationIssueSeverity.MEDIUM
    filename: str


class SigmahqFilenameConventionValidator(SigmaRuleValidator):
    """Check a rule filename against SigmaHQ filename convention."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        filename_pattern = re.compile(r"[a-z0-9_]{10,90}\.yml")
        if rule.source is not None:
            filename = rule.source.path.name
            if filename_pattern.match(filename) is None or not "_" in filename:
                return [SigmahqFilenameConventionIssue(rule, filename)]
        return []


@dataclass
class SigmahqFilenamePrefixIssue(SigmaValidationIssue):
    description: ClassVar[
        str
    ] = "The rule filename prefix doesn't match the SigmaHQ convention"
    severity: ClassVar[
        SigmaValidationIssueSeverity
    ] = SigmaValidationIssueSeverity.MEDIUM
    filename: str
    logsource: SigmaLogSource
    prefix: str


class SigmahqFilenamePrefixValidator(SigmaRuleValidator):
    """Check a rule filename against SigmaHQ filename prefix convention."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.source is not None:
            filename = rule.source.path.name
            logsource = rule.logsource

            if logsource in config.sigmahq_logsource_filepattern:
                if not filename.startswith(
                    config.sigmahq_logsource_filepattern[logsource]
                ):
                    return [
                        SigmahqFilenamePrefixIssue(
                            rule,
                            filename,
                            logsource,
                            config.sigmahq_logsource_filepattern[logsource],
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
