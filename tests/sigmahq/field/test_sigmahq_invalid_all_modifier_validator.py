import pytest
from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression

from sigma.validators.sigmahq.field import (
    SigmahqInvalidAllModifierIssue,
    SigmahqInvalidAllModifierValidator,
)


def test_validator_SigmahqInvalidAllModifierIssue():
    """Test that all modifier with single value is detected"""
    validator = SigmahqInvalidAllModifierValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqInvalidAllModifierIssue([rule], "CommandLine")]


def test_validator_SigmahqInvalidAllModifierIssue_valid():
    """Test that all modifier with multiple values is accepted"""
    validator = SigmahqInvalidAllModifierValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []
