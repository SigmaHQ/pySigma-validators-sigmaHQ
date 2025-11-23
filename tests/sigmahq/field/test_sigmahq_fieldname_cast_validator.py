import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.field import (
    SigmahqFieldnameCastIssue,
    SigmahqFieldnameCastValidator,
)


def test_validator_SigmahqFieldnameCast():
    """Test that field name casting errors are detected"""
    validator = SigmahqFieldnameCastValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqFieldnameCastIssue([rule], "commandline")]


def test_validator_SigmahqFieldnameCast_valid():
    """Test that valid field name casting is accepted"""
    validator = SigmahqFieldnameCastValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldnameCast_valid_new_logsource():
    """Test that new log sources with custom field names are accepted"""
    validator = SigmahqFieldnameCastValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldnameCast():
    """Test that field name casting errors are detected"""
    validator = SigmahqFieldnameCastValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqFieldnameCastIssue([rule], "commandline")]


def test_validator_SigmahqFieldnameCast_valid():
    """Test that valid field name casting is accepted"""
    validator = SigmahqFieldnameCastValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldnameCast_valid_new_logsource():
    """Test that new log sources with custom field names are accepted"""
    validator = SigmahqFieldnameCastValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []
