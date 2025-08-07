import re
from dataclasses import dataclass
from typing import ClassVar, Dict, List

from sigma.rule import SigmaRule, SigmaLogSource, SigmaRuleBase

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
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    filename: str


class SigmahqFilenameConventionValidator(SigmaRuleValidator):
    """Check a rule filename against SigmaHQ filename convention."""

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        filename_pattern = re.compile(r"[a-z0-9_]{10,90}\.yml")
        if rule.source is not None:
            filename = rule.source.path.name
            if filename_pattern.match(filename) is None or not "_" in filename:
                return [SigmahqFilenameConventionIssue([rule], filename)]
        return []


@dataclass
class SigmahqFilenamePrefixIssue(SigmaValidationIssue):
    description: ClassVar[str] = "The rule filename prefix doesn't match the SigmaHQ convention"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    filename: str
    logsource: SigmaLogSource
    prefix: str


class SigmahqFilenamePrefixValidator(SigmaRuleValidator):
    """Check a rule filename against SigmaHQ filename prefix convention."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.source is not None:
            filename = rule.source.path.name
            logsource = SigmaLogSource(
                category=rule.logsource.category,
                product=rule.logsource.product,
                service=rule.logsource.service,
            )

            if logsource in config.sigmahq_logsource_filepattern:
                if not filename.startswith(config.sigmahq_logsource_filepattern[logsource]):
                    return [
                        SigmahqFilenamePrefixIssue(
                            [rule],
                            filename,
                            rule.logsource,
                            config.sigmahq_logsource_filepattern[logsource],
                        )
                    ]
            else:
                # check only product but must exist
                if rule.logsource.product:
                    logsource = SigmaLogSource(
                        category=None, product=rule.logsource.product, service=None
                    )
                    if (
                        logsource in config.sigmahq_logsource_filepattern
                        and not filename.startswith(config.sigmahq_logsource_filepattern[logsource])
                    ):
                        return [
                            SigmahqFilenamePrefixIssue(
                                [rule],
                                filename,
                                rule.logsource,
                                config.sigmahq_logsource_filepattern[logsource],
                            )
                        ]
        return []
