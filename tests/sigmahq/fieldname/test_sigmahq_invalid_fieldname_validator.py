from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.fieldname import (
    SigmahqInvalidFieldnameIssue,
    SigmahqInvalidFieldnameValidator,
)


def test_validator_SigmahqInvalidFieldname():
    """Test that invalid field names are detected"""
    validator = SigmahqInvalidFieldnameValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: 'error'
            images: '/cmd.exe'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqInvalidFieldnameIssue([detection_rule], "images")
    ]


def test_validator_SigmahqInvalidFieldname_valid():
    """Test that valid field names are accepted"""
    validator = SigmahqInvalidFieldnameValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: 'error'
            Image: '/cmd.exe'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqInvalidFieldname_valid_new_logsource():
    """Test that new log sources with custom field names are accepted"""
    validator = SigmahqInvalidFieldnameValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: frack
    detection:
        sel:
            MyCommandLines: 'error' # should be MyCommandLine
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqInvalidFieldname_correlation():
    """Test that invalid field names are detected in correlation rules"""
    validator = SigmahqInvalidFieldnameValidator()
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


def test_validator_SigmahqInvalidFieldname_correlation_valid():
    """Test that valid field names in correlation rules are accepted"""
    validator = SigmahqInvalidFieldnameValidator()
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
