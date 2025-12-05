from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule

from sigma.validators.sigmahq.modifier import (
    SigmahqInvalidAllModifierIssue,
    SigmahqInvalidAllModifierValidator,
)


def test_validator_SigmahqInvalidAllModifierIssue():
    """Test that all modifier with single value is detected"""
    validator = SigmahqInvalidAllModifierValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Use All modificator
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|all: 'one'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqInvalidAllModifierIssue([detection_rule], "CommandLine")
    ]


def test_validator_SigmahqInvalidAllModifierIssue_valid():
    """Test that all modifier with multiple values is valid"""
    validator = SigmahqInvalidAllModifierValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Use All modificator
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|all:
                - 'one'
                - 'two'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqInvalidAllModifierIssue_correlation_rule():
    """Test that the validator works correctly with SigmaCorrelationRule (should not detect issues)"""
    validator = SigmahqInvalidAllModifierValidator()
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
