import pytest
from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression
from sigma.validators.sigmahq.field import (
    SigmahqFieldDuplicateValueIssue,
    SigmahqFieldDuplicateValueValidator,
)


def test_validator_SigmahqFieldDuplicateValueIssue():
    """Test that duplicate case insensitive values are detected"""
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|all: 
              - 'one'
              - 'two'
              - 'three'
              - 'Two'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqFieldDuplicateValueIssue([rule], "CommandLine", "Two")
    ]


def test_validator_SigmahqFieldDuplicateValueIssue_base64():
    """Test that base64 modifier doesn't trigger duplicate detection"""
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Base64 Duplicate Case Sensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|base64: 
              - 'one'
              - 'two'
              - 'three'
              - 'Two'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue_re():
    """Test that regex modifier doesn't trigger duplicate detection"""
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Re Duplicate Case Sensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|re: 
              - 'test.*Test'
              - 'test.*test'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue_cased():
    """Test that cased modifier doesn't trigger duplicate detection"""
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Cased Duplicate Case Sensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|cased|contains:
              - ':\\wIndows\\'
              - ':\\wiNdows\\'
              - ':\\winDows\\'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue_casesensitive():
    """Test that case sensitive duplicates are detected"""
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Re Duplicate Case Sensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|re: 
              - 'one'
              - 'One'
              - 'two'
              - 'three'
              - 'Two'
              - 'One'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqFieldDuplicateValueIssue(
            [rule], "CommandLine", str(SigmaRegularExpression(regexp="One", flags=set()))
        )
    ]


def test_validator_SigmahqFieldDuplicateValueIssue_valid():
    """Test that valid non-duplicate values are accepted"""
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Cased Duplicate 
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|contains:
              - 'azertyy'
              - 'qwerty'
        condition: sel
    """
    )
    assert validator.validate(rule) == []
