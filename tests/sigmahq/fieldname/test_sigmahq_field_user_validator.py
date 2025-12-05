from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.fieldname import (
    SigmahqFieldUserIssue,
    SigmahqFieldUserValidator,
)


def test_validator_SigmahqFieldUserValidator_valid():
    """Test that localized user names are detected"""
    validator = SigmahqFieldUserValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            UserName: 'root'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqFieldUserValidator_detection_rule():
    """Test that localized user names are detected in detection rules"""
    validator = SigmahqFieldUserValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            UserName: 'AUTORITE NT'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqFieldUserIssue([detection_rule], "UserName", "AUTORITE NT")
    ]


def test_validator_SigmahqFieldUserValidator_correlation_rule():
    """Test that localized user names are detected in correlation rules"""
    validator = SigmahqFieldUserValidator()
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


def test_validator_SigmahqFieldUserValidator_correlation_rule_with_user_field():
    """Test that localized user names are detected in correlation rules with user fields"""
    validator = SigmahqFieldUserValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation With User
    id: 0e95725d-7320-415d-80f7-004da920fc12
    correlation:
        type: event_count
        rules:
            - 5638f7c0-ac70-491d-8465-2a65075e0d87
        timespan: 1h
        group-by:
            - ComputerName
            - UserName
        condition:
            gte: 100
    """
    )
    assert validator.validate(correlation_rule) == []
