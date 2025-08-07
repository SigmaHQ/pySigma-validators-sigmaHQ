# sigma/validators/sigmahq/check_detection.py

from dataclasses import dataclass
from typing import List, Union, ClassVar, Set, Tuple

from sigma.rule import (
    SigmaRule,
    SigmaDetectionItem,
    SigmaLogSource,
)
from sigma.correlations import SigmaCorrelationRule

from sigma.validators.base import (
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
    SigmaDetectionItemValidator,
)

from sigma.modifiers import SigmaRegularExpressionModifier
from sigma.types import SigmaRegularExpression

from .config import ConfigHQ

config = ConfigHQ()


@dataclass
class SigmahqCategoryEventIdIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses a windows logsource category that doesn't require the use of an EventID field"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqCategoryEventIdValidator(SigmaDetectionItemValidator):
    """Checks if a rule uses an EventID field with a windows category logsource that doesn't require it."""

    def validate(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> List[SigmaValidationIssue]:
        # Only check SigmaRule objects, not SigmaCorrelationRule
        if isinstance(rule, SigmaRule):
            if (
                rule.logsource.product == "windows"
                and rule.logsource.category in config.windows_no_eventid
            ):
                return super().validate(rule)
        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field is not None and detection_item.field == "EventID":
            return [SigmahqCategoryEventIdIssue([self.rule])]
        else:
            return []


@dataclass
class SigmahqCategoryWindowsProviderNameIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses a windows logsource category that doesn't require the use of the Provider_Name field"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqCategoryWindowsProviderNameValidator(SigmaDetectionItemValidator):
    """Checks if a rule uses a Provider_Name field with a windows category logsource that doesn't require it."""

    def validate(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> List[SigmaValidationIssue]:
        # Only check SigmaRule objects, not SigmaCorrelationRule
        if isinstance(rule, SigmaRule) and rule.logsource.product=="windows":
            key=SigmaLogSource(product=rule.logsource.product, category=rule.logsource.category, service=None)
            if key in config.windows_provider_name:
                self.list_provider = config.windows_provider_name[key]
                return super().validate(rule)
        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field is not None and detection_item.field == "Provider_Name":
            # Check each value in the detection item against our list of providers
            for value in detection_item.value:
                if str(value) in self.list_provider:
                    return [SigmahqCategoryWindowsProviderNameIssue([self.rule])]
        return []


@dataclass
class SigmahqUnsupportedRegexGroupConstructIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses an unsupported regular expression group construct. Construct such as positive and negative lookahead, positive and negative lookbehind as well as atomic groups are currently unsupported."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    unsupported_regexp: str


class SigmahqUnsupportedRegexGroupConstructValidator(SigmaDetectionItemValidator):
    """Checks if a rule uses unsupported regular expression group constructs."""

    regex_list: Tuple[str, ...] = (
        "(?=",
        "(?!",
        "(?<=",
        "(?<!",
        "(?>",
    )

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        unsupported_regexps: Set[str] = set()

        if SigmaRegularExpressionModifier in detection_item.modifiers:
            for value in detection_item.value:
                if isinstance(value, SigmaRegularExpression):
                    regexp_value = str(value.regexp)
                    for unsupported_group_construct in self.regex_list:
                        if unsupported_group_construct in regexp_value:
                            unsupported_regexps.add(regexp_value)

        return [
            SigmahqUnsupportedRegexGroupConstructIssue([self.rule], regexp)
            for regexp in unsupported_regexps
        ]
