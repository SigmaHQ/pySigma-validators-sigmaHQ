from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetectionItem, SigmaRule

from sigma.validators.sigmahq.windows import (
    SigmahqWindowsPathNotAbsoluteIssue,
    SigmahqWindowsPathNotAbsoluteValidator,
)


def test_validator_SigmahqWindowsPathNotAbsolute_partial_path():
    """Test that an exact match on a partial path is detected."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Partial Path
status: test
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image: '\SystemResetPlatform.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsPathNotAbsoluteIssue([detection_rule], "Image", r"\SystemResetPlatform.exe")
    ]


def test_validator_SigmahqWindowsPathNotAbsolute_file_name():
    """Test that an exact match on a file name without a path is detected."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: File Name Only
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'TeamViewer_Desktop.exe'
        ParentImage: 'TeamViewer_Service.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsPathNotAbsoluteIssue([detection_rule], "Image", "TeamViewer_Desktop.exe"),
        SigmahqWindowsPathNotAbsoluteIssue(
            [detection_rule], "ParentImage", "TeamViewer_Service.exe"
        ),
    ]


def test_validator_SigmahqWindowsPathNotAbsolute_colon_start():
    """Test that an exact match that starts with a colon is detected."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Colon Start
status: test
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded: ':\ProgramShared\mscoree.dll'
        TargetFilename: 'host_ip.ps1'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqWindowsPathNotAbsoluteIssue(
            [detection_rule], "ImageLoaded", r":\ProgramShared\mscoree.dll"
        ),
        SigmahqWindowsPathNotAbsoluteIssue([detection_rule], "TargetFilename", "host_ip.ps1"),
    ]


def test_validator_SigmahqWindowsPathNotAbsolute_absolute_paths_valid():
    """Test that absolute paths are accepted."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Absolute Paths
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\Windows\System32\svchost.exe'
        ParentImage: '\\\\server\share\svchost.exe'
        SourceImage: '\Device\HarddiskVolume1\Windows\System32\svchost.exe'
        TargetImage: '\SystemRoot\System32\svchost.exe'
        ImageLoaded: '\??\C:\Windows\System32\ntdll.dll'
        TargetFilename: '%SystemRoot%\System32\ntdll.dll'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathNotAbsolute_pseudo_process_names_valid():
    """Test that pseudo-process names are accepted."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Pseudo Process Names
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - 'System'
            - 'Registry'
            - 'Idle'
            - 'MemCompression'
            - 'vmmem'
            - 'vmmemWSL'
            - '-'
            - '<unknown process>'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathNotAbsolute_wildcard_valid():
    """Test that values with wildcards are not checked."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Wildcard
status: test
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename: 'host_ip*.ps1'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathNotAbsolute_empty_and_null_valid():
    """Test that empty and null values are ignored."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Empty Value
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: ''
        ParentImage: null
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathNotAbsolute_not_windows():
    """Test that rules for other products are not checked."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Linux Path
status: test
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image: 'bash'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathNotAbsolute_correlation_rule():
    """Test that correlation rules are not checked."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
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


def test_validator_SigmahqWindowsPathNotAbsolute_non_path_field_skipped():
    """Test that fields not in PATH_FIELDS are ignored (covers guard on line 105)."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Non Path Field
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'not_a_path.exe'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqWindowsPathNotAbsolute_original_value_none_fallback():
    """Test the fallback to `value` when `original_value` is None (covers line 71)."""
    validator = SigmahqWindowsPathNotAbsoluteValidator()
    detection_rule = SigmaRule.from_yaml(
        r"""
title: Original Value None
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'partial.exe'
    condition: selection
"""
    )
    # Force original_value to None to exercise the fallback path.
    for detection in detection_rule.detection.detections.values():
        for item in detection.detection_items:
            if isinstance(item, SigmaDetectionItem):
                item.original_value = None

    assert validator.validate(detection_rule) == [
        SigmahqWindowsPathNotAbsoluteIssue([detection_rule], "Image", "partial.exe")
    ]
