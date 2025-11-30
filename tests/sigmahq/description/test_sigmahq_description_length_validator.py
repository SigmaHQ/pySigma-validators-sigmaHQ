# tests/sigmahq/test_sigmahq_description_length_validator.py
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.description import (
    SigmahqDescriptionLengthIssue,
    SigmahqDescriptionLengthValidator,
)


def test_validator_SigmahqDescriptionLength_invalid():
    """Test that short descriptions trigger the validator issue"""
    validator = SigmahqDescriptionLengthValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [SigmahqDescriptionLengthIssue([detection_rule])]


def test_validator_SigmahqDescriptionLength_valid():
    """Test that valid descriptions pass validation"""
    validator = SigmahqDescriptionLengthValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: a simple description to test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqDescriptionLength_valid_detection_rule():
    """Test that valid detection rules with adequate description length pass validation"""
    validator = SigmahqDescriptionLengthValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: This is a valid description that meets the minimum length requirement for detection rules
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqDescriptionLength_none():
    """Test that None descriptions trigger the validator issue"""
    validator = SigmahqDescriptionLengthValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqDescriptionLength_empty():
    """Test that empty descriptions trigger the validator issue"""
    validator = SigmahqDescriptionLengthValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ""
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [SigmahqDescriptionLengthIssue([detection_rule])]


def test_validator_SigmahqDescriptionLength_correlation_invalid():
    """Test that short correlation rule descriptions trigger the validator issue"""
    validator = SigmahqDescriptionLengthValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    description: Short
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
    assert validator.validate(correlation_rule) == [
        SigmahqDescriptionLengthIssue([correlation_rule])
    ]


def test_validator_SigmahqDescriptionLength_correlation_valid():
    """Test that valid correlation rule descriptions pass validation"""
    validator = SigmahqDescriptionLengthValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    description: This is a test correlation rule with adequate length
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


def test_validator_SigmahqDescriptionLength_correlation_empty():
    """Test that empty correlation rule descriptions trigger the validator issue"""
    validator = SigmahqDescriptionLengthValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    description: ""
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
    assert validator.validate(correlation_rule) == [
        SigmahqDescriptionLengthIssue([correlation_rule])
    ]
