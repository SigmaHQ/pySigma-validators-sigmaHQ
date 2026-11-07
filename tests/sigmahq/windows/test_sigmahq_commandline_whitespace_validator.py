from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.windows import (
    SigmahqWindowsCommandLineWhitespaceIssue,
    SigmahqWindowsCommandLineWhitespaceValidator,
)


def test_validator_SigmahqWindowsCommandLineWhitespace_leading_space():
    """Test that an exact command line value with a leading space is detected."""
    validator = SigmahqWindowsCommandLineWhitespaceValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Leading Space
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: ' -dhl'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsCommandLineWhitespaceIssue([detection_rule], "CommandLine", " -dhl")
    ]


def test_validator_SigmahqWindowsCommandLineWhitespace_trailing_space():
    """Test that an exact parent command line value with a trailing space is detected."""
    validator = SigmahqWindowsCommandLineWhitespaceValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Trailing Space
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentCommandLine: 'cmd.exe /c '
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsCommandLineWhitespaceIssue(
            [detection_rule], "ParentCommandLine", "cmd.exe /c "
        )
    ]


def test_validator_SigmahqWindowsCommandLineWhitespace_valid():
    """Test that an exact command line without surrounding whitespace is accepted."""
    validator = SigmahqWindowsCommandLineWhitespaceValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Valid Command Line
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'RunWizard'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsCommandLineWhitespace_modifier_valid():
    """Test that command line values with a modifier are not checked."""
    validator = SigmahqWindowsCommandLineWhitespaceValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Contains Modifier
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ' -dhl'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsCommandLineWhitespace_empty_and_null_valid():
    """Test that empty and null command line values are ignored."""
    validator = SigmahqWindowsCommandLineWhitespaceValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Empty Command Line
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: ''
        ParentCommandLine: null
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsCommandLineWhitespace_not_windows():
    """Test that rules for other products are not checked."""
    validator = SigmahqWindowsCommandLineWhitespaceValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Linux Command Line
status: test
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine: ' bash'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsCommandLineWhitespace_correlation_rule():
    """Test that correlation rules are not checked."""
    validator = SigmahqWindowsCommandLineWhitespaceValidator()
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
