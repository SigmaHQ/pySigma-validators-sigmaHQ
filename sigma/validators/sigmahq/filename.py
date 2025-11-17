import re
from dataclasses import dataclass
from typing import ClassVar, Dict, List

from sigma.rule import SigmaRule, SigmaLogSource, SigmaRuleBase
from sigma.correlations import SigmaCorrelationRule

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


@dataclass
class SigmahqCorrelationFilenamePrefixIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Correlation rule filename must start with 'correlation_'"
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


class SigmahqCorrelationFilenamePrefixValidator(SigmaRuleValidator):
    """Check that correlation rule filenames start with 'correlation_'."""

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        # Only validate correlation rules
        if not isinstance(rule, SigmaCorrelationRule):
            return []

        if rule.source is not None:
            filename = rule.source.path.name

            # All correlation files (pure or combined) must start with 'correlation_'
            if not filename.startswith("correlation_"):
                return [SigmahqCorrelationFilenamePrefixIssue([rule], filename)]

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

    def _is_combined_file(self, rule: SigmaRuleBase) -> bool:
        """
        Check if the file contains a combined format (both detection(s) and correlation rules).
        This is determined by reading the file and checking for YAML document separator.
        """
        if rule.source is None:
            return False

        try:
            with open(rule.source.path, "r", encoding="utf-8") as f:
                content = f.read()
                # Check if file contains both correlation and detection/logsource sections
                has_separator = "\n---\n" in content or content.startswith("---\n")
                has_correlation = "correlation:" in content
                has_logsource = "logsource:" in content

                # Combined if it has separator and both correlation and logsource
                return has_separator and has_correlation and has_logsource
        except:
            return False

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []

        # Skip validation for combined format files (they can have multiple logsources)
        if self._is_combined_file(rule):
            return []

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
