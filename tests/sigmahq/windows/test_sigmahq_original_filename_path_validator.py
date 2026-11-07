from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.windows import (
    SigmahqWindowsOriginalFileNamePathIssue,
    SigmahqWindowsOriginalFileNamePathValidator,
)


def test_validator_SigmahqWindowsOriginalFileNamePath_leading_backslash():
    """Test that a leading backslash in OriginalFileName is detected."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Leading Backslash
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: '\msiexec.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsOriginalFileNamePathIssue(
            [detection_rule], "OriginalFileName", r"\msiexec.exe"
        )
    ]


def test_validator_SigmahqWindowsOriginalFileNamePath_full_path():
    """Test that a full path in OriginalFileName is detected."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Full Path
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'C:\Windows\System32\msiexec.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsOriginalFileNamePathIssue(
            [detection_rule], "OriginalFileName", "C:\\Windows\\System32\\msiexec.exe"
        )
    ]


def test_validator_SigmahqWindowsOriginalFileNamePath_forward_slash():
    """Test that a forward slash in OriginalFileName is detected."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Forward Slash
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'some/file.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsOriginalFileNamePathIssue(
            [detection_rule], "OriginalFileName", "some/file.exe"
        )
    ]


def test_validator_SigmahqWindowsOriginalFileNamePath_valid():
    """Test that a bare filename is accepted."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Valid Filename
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'msiexec.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsOriginalFileNamePath_endswith_valid():
    """Test that endswith with a bare filename is accepted."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Endswith Valid
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName|endswith: 'msiexec.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsOriginalFileNamePath_endswith_backslash():
    """Test that endswith with a backslash is detected."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Endswith Backslash
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName|endswith: '\msiexec.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsOriginalFileNamePathIssue(
            [detection_rule], "OriginalFileName", r"\msiexec.exe"
        )
    ]


def test_validator_SigmahqWindowsOriginalFileNamePath_wildcard_valid():
    """Test that a wildcard value is not checked."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Wildcard
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: '*msiexec*'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsOriginalFileNamePath_not_windows():
    """Test that rules for other products are not checked."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Linux Rule
status: test
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        OriginalFileName: '/usr/bin/msiexec'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsOriginalFileNamePath_correlation_rule():
    """Test that correlation rules are not checked."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
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


def test_validator_SigmahqWindowsOriginalFileNamePath_other_field_ignored():
    """Test that other fields are not checked."""
    validator = SigmahqWindowsOriginalFileNamePathValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Other Field
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '\msiexec.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []
