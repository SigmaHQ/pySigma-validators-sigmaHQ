from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.detection import (
    SigmahqCategoryEventIdIssue,
    SigmahqCategoryEventIdValidator,
    SigmahqCategoryWindowsProviderNameIssue,
    SigmahqCategoryWindowsProviderNameValidator,
    SigmahqUnsupportedRegexGroupConstructIssue,
    SigmahqUnsupportedRegexGroupConstructValidator,
)


def test_validator_SigmahqCategoryEventId():
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: ps_module
    detection:
        sel:
            field: path\\*something
            EventID: 4103
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqCategoryEventIdIssue(rule)]


def test_validator_SigmahqCategoryEventId_valid():
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: ps_module
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqCategoryWindowsProviderName():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field: path\\*something
            Provider_Name: Microsoft-Windows-Sysmon
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqCategoryWindowsProviderNameIssue(rule)]


def test_validator_SigmahqCategoryWindowsProviderName_valid():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqUnsupportedRegexGroupConstruct():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: 'A(?=B)'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "A(?=B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_valid():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: 'a\w+b'
        condition: sel
    """
    )
    assert validator.validate(rule) == []
