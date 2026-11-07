from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.windows import (
    SigmahqWindowsPathStartswithIssue,
    SigmahqWindowsPathStartswithValidator,
)


def test_validator_SigmahqWindowsPathStartswith_colon():
    """Test that a startswith value beginning with a colon is detected."""
    validator = SigmahqWindowsPathStartswithValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Colon Start
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|startswith: ':\Program Files'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsPathStartswithIssue(
            [detection_rule], "Image", r":\Program Files", "value starts with a colon"
        )
    ]


def test_validator_SigmahqWindowsPathStartswith_leading_space():
    """Test that a startswith value beginning with a space is detected."""
    validator = SigmahqWindowsPathStartswithValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Leading Space
status: test
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|startswith:
            - ' C:\Program Files (x86)\Siber Systems\AI RoboForm\'
            - ' C:\Program Files\Siber Systems\AI RoboForm\'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsPathStartswithIssue(
            [detection_rule],
            "Image",
            " C:\\Program Files (x86)\\Siber Systems\\AI RoboForm\\",
            "value starts with a space",
        ),
        SigmahqWindowsPathStartswithIssue(
            [detection_rule],
            "Image",
            " C:\\Program Files\\Siber Systems\\AI RoboForm\\",
            "value starts with a space",
        ),
    ]


def test_validator_SigmahqWindowsPathStartswith_drive_letter_without_colon():
    """Test that a drive letter without a colon is detected."""
    validator = SigmahqWindowsPathStartswithValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Drive Letter Without Colon
status: test
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|startswith: 'C\Windows\WinSxS\'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsPathStartswithIssue(
            [detection_rule],
            "ImageLoaded",
            "C\\Windows\\WinSxS\\",
            "drive letter without a colon",
        )
    ]


def test_validator_SigmahqWindowsPathStartswith_valid():
    """Test that valid path prefixes are accepted."""
    validator = SigmahqWindowsPathStartswithValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Valid Prefixes
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|startswith: 'C:\Program Files\'
        - Image|startswith: '\\\\server\share\'
        - Image|startswith: '\Windows\'
        - Image|startswith: '%SystemRoot%\'
        - Image|startswith: '/usr/'
    condition: 1 of selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathStartswith_other_modifier_valid():
    """Test that other modifiers on the same field are not checked."""
    validator = SigmahqWindowsPathStartswithValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Contains Modifier
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: ':\Program Files'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathStartswith_not_windows():
    """Test that rules for other products are not checked."""
    validator = SigmahqWindowsPathStartswithValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Linux Prefix
status: test
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|startswith: ':/usr/bin'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathStartswith_correlation_rule():
    """Test that correlation rules are not checked."""
    validator = SigmahqWindowsPathStartswithValidator()
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
