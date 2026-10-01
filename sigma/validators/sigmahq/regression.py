import re
from dataclasses import dataclass
from typing import ClassVar, List

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

# The path mirrors the rule location inside one of the rule trees, and always
# points at the info.yml of the rule's own regression data folder.
_RE_REGRESSION_PATH = re.compile(
    r"^regression_data/"
    r"(?:rules|rules-emerging-threats|rules-threat-hunting|rules-compliance|rules-dfir)"
    r"/[^\s].*/info\.yml$"
)


@dataclass
class SigmahqRegressionPathNotStringIssue(SigmaValidationIssue):
    description: ClassVar[str] = "regression_tests_path must be a string"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


@dataclass
class SigmahqRegressionPathInvalidFormatIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "regression_tests_path must point at an info.yml inside the rule's mirrored "
        "regression_data folder, e.g. "
        "regression_data/rules/windows/process_creation/my_rule/info.yml"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    path: str


class SigmahqRegressionPathValidator(SigmaRuleValidator):
    """Checks the format of the regression_tests_path field.

    Only the shape of the value is validated when the field is present. This
    validator deliberately does not require the field on test or stable rules:
    the vast majority of them carry no regression data, so such a requirement
    would flag thousands of existing rules.
    """

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not rule.custom_attributes:
            return []

        path = rule.custom_attributes.get("regression_tests_path")
        if path is None:
            return []

        if not isinstance(path, str):
            return [SigmahqRegressionPathNotStringIssue([rule])]

        if not _RE_REGRESSION_PATH.match(path):
            return [SigmahqRegressionPathInvalidFormatIssue([rule], path=path)]
        return []
