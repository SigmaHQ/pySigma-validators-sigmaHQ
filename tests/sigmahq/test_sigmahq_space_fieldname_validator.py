from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.field import (
    SigmahqSpaceFieldNameIssue,
    SigmahqSpaceFieldNameValidator,
)


def test_validator_SigmahqSpaceFieldname():
    """Test that space in field names are detected"""
    validator = SigmahqSpaceFieldNameValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
            space name: 'error'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqSpaceFieldNameIssue([detection_rule], "space name")
    ]


def test_validator_SigmahqSpaceFieldname_valid():
    """Test that underscore in field names are valid"""
    validator = SigmahqSpaceFieldNameValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
            space_name: 'error'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqSpaceFieldNameValidator():
    """Test that space in field names are detected"""
    validator = SigmahqSpaceFieldNameValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Command Line: 'invalid'
            CommandLine: 'valid'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqSpaceFieldNameIssue([detection_rule], "Command Line")
    ]


def test_validator_SigmahqSpaceFieldNameValidator_valid():
    """Test that underscore in field names are valid"""
    validator = SigmahqSpaceFieldNameValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Command_Line: 'valid'
            CommandLine: 'valid'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqRedundantModified_correlation_valid():
    validator = SigmahqSpaceFieldNameValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    date: 2022-01-01
    modified: 2023-01-01
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
