from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.detection import (
    SigmahqCategoryWindowsProviderNameIssue,
    SigmahqCategoryWindowsProviderNameValidator,
)


def test_validator_SigmahqCategoryWindowsProviderName():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [
        SigmahqCategoryWindowsProviderNameIssue([detection_rule])
    ]


def test_validator_SigmahqCategoryWindowsProviderName_valid():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqCategoryWindowsProviderName_other():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqCategoryWindowsProviderName_multiple_values():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [
        SigmahqCategoryWindowsProviderNameIssue([detection_rule])
    ]


def test_validator_SigmahqCategoryWindowsProviderName_no_provider():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqCategoryWindowsProviderName_no_windows():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: Something
detection:
    sel:
        field: path\\*something
        Provider_Name: Some-Other-Provider
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_correlation_valid():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
author: Test Author
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert validator.validate(correlation_rule) == []
