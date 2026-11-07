import re
from dataclasses import dataclass
from typing import ClassVar, List, Optional, Tuple

from sigma.correlations import SigmaCorrelationRule
from sigma.modifiers import SigmaStartswithModifier
from sigma.rule import SigmaRule
from sigma.types import SigmaString, SigmaType
from sigma.validators.base import (
    SigmaDetectionItem,
    SigmaDetectionItemValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

PATH_FIELDS: Tuple[str, ...] = (
    "Image",
    "ParentImage",
    "ImageLoaded",
    "TargetFilename",
    "SourceImage",
    "TargetImage",
)
COMMAND_LINE_FIELDS: Tuple[str, ...] = ("CommandLine", "ParentCommandLine")
PSEUDO_PROCESS_NAMES = frozenset(
    (
        "system",
        "registry",
        "idle",
        "memcompression",
        "vmmem",
        "vmmemwsl",
        "-",
        "<unknown process>",
    )
)
ABSOLUTE_PATH_PREFIXES: Tuple[str, ...] = (
    "\\\\",
    "\\Device\\",
    "\\SystemRoot\\",
    "\\??\\",
    "%",
    "/",
)
ABSOLUTE_PATH_PREFIXES_CASEFOLDED: Tuple[str, ...] = tuple(
    prefix.casefold() for prefix in ABSOLUTE_PATH_PREFIXES
)
PATH_SEPARATORS: Tuple[str, ...] = ("\\", "/")
DRIVE_LETTER = re.compile(r"^[A-Za-z]:")
DRIVE_LETTER_WITHOUT_COLON = re.compile(r"^[A-Za-z](?!:)")


def _is_windows_rule(rule: SigmaRule) -> bool:
    """Return True for a detection rule of the Windows product."""
    return rule.logsource.product == "windows"


def _plain_value(value: SigmaType) -> Optional[str]:
    """Return the literal string of a SigmaString without wildcard or placeholder."""
    if not isinstance(value, SigmaString):
        return None
    if any(not isinstance(part, str) for part in value.s):
        return None
    return "".join(value.s)


def _original_values(detection_item: SigmaDetectionItem) -> List[SigmaType]:
    """Return the values before modifier application."""
    if detection_item.original_value is not None:
        return detection_item.original_value
    return detection_item.value


def _is_absolute_path(value: str) -> bool:
    if DRIVE_LETTER.match(value):
        return True
    return value.casefold().startswith(ABSOLUTE_PATH_PREFIXES_CASEFOLDED)


@dataclass
class SigmahqWindowsPathNotAbsoluteIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses an exact match on a Windows path field with a value that is not an absolute path"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str
    value: str


class SigmahqWindowsPathNotAbsoluteValidator(SigmaDetectionItemValidator):
    """Check exact matches on Windows path fields that cannot be a full path."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules.
        if not isinstance(rule, SigmaRule):
            return []
        if not _is_windows_rule(rule):
            return []
        return super().validate(rule)

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field not in PATH_FIELDS or detection_item.modifiers:
            return []

        return [
            SigmahqWindowsPathNotAbsoluteIssue([self.rule], detection_item.field, plain_value)
            for value in _original_values(detection_item)
            if (plain_value := _plain_value(value)) is not None
            and plain_value != ""
            and plain_value.casefold() not in PSEUDO_PROCESS_NAMES
            and not _is_absolute_path(plain_value)
        ]


@dataclass
class SigmahqWindowsPathFolderIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses an exact match on a Windows path field with a folder path"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str
    value: str


class SigmahqWindowsPathFolderValidator(SigmaDetectionItemValidator):
    """Check exact matches on Windows path fields that end with a path separator."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules.
        if not isinstance(rule, SigmaRule):
            return []
        if not _is_windows_rule(rule):
            return []
        return super().validate(rule)

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field not in PATH_FIELDS or detection_item.modifiers:
            return []

        return [
            SigmahqWindowsPathFolderIssue([self.rule], detection_item.field, plain_value)
            for value in _original_values(detection_item)
            if (plain_value := _plain_value(value)) is not None
            and plain_value != ""
            and plain_value.casefold() not in PSEUDO_PROCESS_NAMES
            and plain_value.endswith(PATH_SEPARATORS)
        ]


@dataclass
class SigmahqWindowsPathStartswithIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses a startswith match on a Windows path field with a value that cannot start a path"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str
    value: str
    reason: str


class SigmahqWindowsPathStartswithValidator(SigmaDetectionItemValidator):
    """Check startswith matches on Windows path fields with a value that cannot start a path."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules.
        if not isinstance(rule, SigmaRule):
            return []
        if not _is_windows_rule(rule):
            return []
        return super().validate(rule)

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if (
            detection_item.field not in PATH_FIELDS
            or SigmaStartswithModifier not in detection_item.modifiers
        ):
            return []

        issues = []
        for value in _original_values(detection_item):
            plain_value = _plain_value(value)
            if plain_value is None or plain_value == "":
                continue
            if plain_value.startswith(":"):
                reason = "value starts with a colon"
            elif plain_value.startswith(" "):
                reason = "value starts with a space"
            elif DRIVE_LETTER_WITHOUT_COLON.match(plain_value):
                reason = "drive letter without a colon"
            else:
                continue
            issues.append(
                SigmahqWindowsPathStartswithIssue(
                    [self.rule], detection_item.field, plain_value, reason
                )
            )
        return issues


@dataclass
class SigmahqWindowsCommandLineWhitespaceIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule uses an exact match on a Windows command line field with leading or trailing "
        "whitespace"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    field: str
    value: str


class SigmahqWindowsCommandLineWhitespaceValidator(SigmaDetectionItemValidator):
    """Check exact matches on Windows command line fields with surrounding whitespace."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        # Only validate SigmaRule (detection rules), not correlation rules.
        if not isinstance(rule, SigmaRule):
            return []
        if not _is_windows_rule(rule):
            return []
        return super().validate(rule)

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> List[SigmaValidationIssue]:
        if detection_item.field not in COMMAND_LINE_FIELDS or detection_item.modifiers:
            return []

        return [
            SigmahqWindowsCommandLineWhitespaceIssue([self.rule], detection_item.field, plain_value)
            for value in _original_values(detection_item)
            if (plain_value := _plain_value(value)) is not None
            and plain_value != plain_value.strip()
        ]
