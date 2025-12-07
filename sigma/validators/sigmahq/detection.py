from dataclasses import dataclass
from typing import ClassVar, List, Set, Tuple

from sigma.rule import (
    SigmaRule,
    SigmaDetectionItem,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.base import (
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
    SigmaDetectionItemValidator,
    SigmaDetectionItem,
)
from sigma.types import SigmaString
from sigma.modifiers import SigmaRegularExpressionModifier

from sigma.validators.sigmahq.data import data_windows_eventid, data_windows_provider


@dataclass
class SigmahqCategoryEventIdIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses a windows logsource category that doesn't require the use of an EventID field"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqCategoryEventIdValidator(SigmaDetectionItemValidator):
    """Checks if a rule uses an EventID field with a windows category logsource that doesn't require it."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []

        if (
            rule.logsource.product == "windows"
            and rule.logsource.category in data_windows_eventid.sigmahq_category_no_eventid
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

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []

        if not rule.logsource.product == "windows":
            return []

        if rule.logsource.category in data_windows_provider.sigmahq_provider_name:
            self.list_provider = data_windows_provider.sigmahq_provider_name[
                rule.logsource.category
            ]
            return super().validate(rule)

        return []

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field is not None and detection_item.field == "Provider_Name":
            for v in detection_item.value:
                if v in self.list_provider:
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
    """Checks if a rule uses an unsupported regular expression group constructs."""

    regex_list: Tuple[str, ...] = (
        "(?=",
        "(?!",
        "(?<=",
        "(?<!",
        "(?>",
    )

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules
        if not isinstance(rule, SigmaRule):
            return []
        return super().validate(rule)

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        unsupported_regexps: Set[str] = set()

        # Check only if the modifier is a regular expression
        if SigmaRegularExpressionModifier in detection_item.modifiers:
            for value in detection_item.value:
                regexp_value = getattr(value, "regexp", None)
                # Validate that regexp_value is an instance of SigmaString
                if isinstance(regexp_value, SigmaString):
                    found_unsupported = False
                    regex_str = str(regexp_value)  # Convert to string

                    for unsupported_group_construct in self.regex_list:
                        if unsupported_group_construct in regex_str:
                            unsupported_regexps.add(regex_str)
                            found_unsupported = True
                            break  # No need to check further once an unsupported pattern is found

        return [
            SigmahqUnsupportedRegexGroupConstructIssue([self.rule], regexp)
            for regexp in unsupported_regexps
        ]
