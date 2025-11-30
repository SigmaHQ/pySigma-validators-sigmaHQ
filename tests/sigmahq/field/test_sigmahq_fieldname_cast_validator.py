from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.field import (
    SigmahqFieldnameCastIssue,
    SigmahqFieldnameCastValidator,
)


def test_validator_SigmahqFieldnameCast():
    """Test that field name casting errors are detected"""
    validator = SigmahqFieldnameCastValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            commandline: 'error'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqFieldnameCastIssue([detection_rule], "commandline")
    ]


def test_validator_SigmahqFieldnameCast_valid():
    """Test that valid field name casting is accepted"""
    validator = SigmahqFieldnameCastValidator()
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
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqFieldnameCast_valid_new_logsource():
    """Test that new log sources with custom field names are accepted"""
    validator = SigmahqFieldnameCastValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: frack
    detection:
        sel:
            MyCommandLine: 'error'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_correlation_rule():
    """Test that localized user names are detected in correlation rules"""
    validator = SigmahqFieldnameCastValidator()
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
