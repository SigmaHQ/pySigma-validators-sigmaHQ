from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.types import SigmaRegularExpression
from sigma.validators.sigmahq.field import (
    SigmahqFieldDuplicateValueIssue,
    SigmahqFieldDuplicateValueValidator,
)


def test_validator_SigmahqFieldDuplicateValueIssue():
    """Test that duplicate case insensitive values are detected"""
    validator = SigmahqFieldDuplicateValueValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [
        SigmahqFieldDuplicateValueIssue([detection_rule], "CommandLine", "Two")
    ]


def test_validator_SigmahqFieldDuplicateValueIssue_base64():
    """Test that base64 modifier doesn't trigger duplicate detection"""
    validator = SigmahqFieldDuplicateValueValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue_re():
    """Test that regex modifier doesn't trigger duplicate detection"""
    validator = SigmahqFieldDuplicateValueValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue_cased():
    """Test that cased modifier doesn't trigger duplicate detection"""
    validator = SigmahqFieldDuplicateValueValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue_casesensitive():
    """Test that case sensitive duplicates are detected"""
    validator = SigmahqFieldDuplicateValueValidator()
    detection_rule = SigmaRule.from_yaml(
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

    # Assuming SigmaRegularExpression is initialized without keyword arguments like this
    assert validator.validate(detection_rule) == [
        SigmahqFieldDuplicateValueIssue(
            [detection_rule],
            "CommandLine",
            str(SigmaRegularExpression("One")),  # Correct initialization
        )
    ]


def test_validator_SigmahqFieldDuplicateValueIssue_valid():
    """Test that valid non-duplicate values are accepted"""
    validator = SigmahqFieldDuplicateValueValidator()
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
