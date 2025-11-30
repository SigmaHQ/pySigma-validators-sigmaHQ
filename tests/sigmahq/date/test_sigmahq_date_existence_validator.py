from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.date import (
    SigmahqDateExistenceIssue,
    SigmahqDateExistenceValidator,
)


def test_validator_SigmahqDateExistence():
    validator = SigmahqDateExistenceValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [SigmahqDateExistenceIssue([detection_rule])]


def test_validator_SigmahqDateExistence_valid():
    validator = SigmahqDateExistenceValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    date: 2023-12-10
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqDate_correlation():
    validator = SigmahqDateExistenceValidator()
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
    assert validator.validate(correlation_rule) == [SigmahqDateExistenceIssue([correlation_rule])]


def test_validator_SigmahqDate_correlation_valid():
    validator = SigmahqDateExistenceValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    date: 2024-01-01
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


def test_validator_SigmahqDateExistence_valid_detection_rule():
    """Test that a valid detection rule with date passes validation"""
    validator = SigmahqDateExistenceValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    date: 2023-12-10
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []
