from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.field import (
    SigmahqFieldUserIssue,
    SigmahqFieldUserValidator,
)


def test_validator_SigmahqFieldUserValidator_valid():
    """Test that localized user names are detected"""
    validator = SigmahqFieldUserValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldUserValidator():
    """Test that localized user names are detected"""
    validator = SigmahqFieldUserValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqFieldUserIssue([rule], "UserName", "AUTORITE NT")]

def test_validator_SigmahqFieldUser_correlation():
    """Test that localized user names are detected in correlation rules"""
    validator = SigmahqFieldUserValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Correlation with localized username
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 1h
    group-by:
        - ComputerName
"""
    )
    assert validator.validate(rule) == []
