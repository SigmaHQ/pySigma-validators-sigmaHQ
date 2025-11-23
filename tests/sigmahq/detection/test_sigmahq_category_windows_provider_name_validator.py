import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.detection import (
    SigmahqCategoryWindowsProviderNameIssue,
    SigmahqCategoryWindowsProviderNameValidator,
)


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
    assert validator.validate(rule) == [SigmahqCategoryWindowsProviderNameIssue([rule])]


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


def test_validator_SigmahqCategoryWindowsProviderName_other():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqCategoryWindowsProviderName_multiple_values():
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
        Provider_Name:
            - Microsoft-Windows-Sysmon
            - Microsoft-Windows-PowerShell
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqCategoryWindowsProviderNameIssue([rule])]


def test_validator_SigmahqCategoryWindowsProviderName_no_provider():
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
        Provider_Name: Some-Other-Provider
    condition: sel
"""
    )
    assert validator.validate(rule) == []
