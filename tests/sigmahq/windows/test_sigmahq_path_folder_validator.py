from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.windows import (
    SigmahqWindowsPathFolderIssue,
    SigmahqWindowsPathFolderValidator,
)


def test_validator_SigmahqWindowsPathFolder():
    """Test that an exact match on a folder path is detected."""
    validator = SigmahqWindowsPathFolderValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Folder Path
status: test
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image: 'C:\Program Files\Microsoft Monitoring Agent\'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsPathFolderIssue(
            [detection_rule], "Image", "C:\\Program Files\\Microsoft Monitoring Agent\\"
        )
    ]


def test_validator_SigmahqWindowsPathFolder_multiple_values():
    """Test that every folder path value is reported."""
    validator = SigmahqWindowsPathFolderValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Folder Paths
status: test
logsource:
    category: registry_delete
    product: windows
detection:
    selection:
        Image:
            - 'C:\Program Files (x86)\Avira\Antivirus\'
            - 'C:\Program Files\Avira\Antivirus\'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsPathFolderIssue(
            [detection_rule], "Image", "C:\\Program Files (x86)\\Avira\\Antivirus\\"
        ),
        SigmahqWindowsPathFolderIssue(
            [detection_rule], "Image", "C:\\Program Files\\Avira\\Antivirus\\"
        ),
    ]


def test_validator_SigmahqWindowsPathFolder_file_path_valid():
    """Test that a file path is accepted."""
    validator = SigmahqWindowsPathFolderValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: File Path
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\Program Files\Avira\Antivirus\avguard.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathFolder_wildcard_valid():
    """Test that a value containing a wildcard is not checked."""
    validator = SigmahqWindowsPathFolderValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Wildcard Folder
status: test
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename: 'C:\Program Files*'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathFolder_pseudo_process_name_valid():
    """Test that pseudo-process names are ignored."""
    validator = SigmahqWindowsPathFolderValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Pseudo Process Name
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '<unknown process>'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathFolder_not_windows():
    """Test that rules for other products are not checked."""
    validator = SigmahqWindowsPathFolderValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Linux Folder Path
status: test
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename: '/etc/sudoers.d/'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathFolder_correlation_rule():
    """Test that correlation rules are not checked."""
    validator = SigmahqWindowsPathFolderValidator()
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


def test_validator_SigmahqWindowsPathFolder_non_path_field_skipped():
    """Test that fields not in PATH_FIELDS are ignored (covers guard on line 142)."""
    validator = SigmahqWindowsPathFolderValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Non Path Field
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'C:\SomeFolder\'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []
