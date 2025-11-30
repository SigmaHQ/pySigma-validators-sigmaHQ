from dataclasses import dataclass
from typing import ClassVar, List

from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqFieldsExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule is using the deprecated field fields"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqFieldsExistenceValidator(SigmaRuleValidator):
    """Checks if a rule is using the deprecated field fields."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if len(rule.fields) > 0:
            return [SigmahqFieldsExistenceIssue([rule])]
        else:
            return []


@dataclass
class SigmahqUnknownFieldIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule uses an unknown field"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    fieldname: List[str]


class SigmahqUnknownFieldValidator(SigmaRuleValidator):
    """Checks if a rule uses an unknown field."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if len(rule.custom_attributes) > 0:
            custom_keys = list(rule.custom_attributes.keys())
            allowed_fields = {"regression_tests_path", "simulation"}

            # For correlation rules, the 'correlation' field is standard, not custom
            if isinstance(rule, SigmaCorrelationRule):
                allowed_fields.add("correlation")

            # Find any custom attributes that are not in the allowed list
            unknown_fields = [key for key in custom_keys if key not in allowed_fields]

            if unknown_fields:
                return [SigmahqUnknownFieldIssue([rule], unknown_fields)]
            else:
                return []
        else:
            return []
