from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.level import (
    SigmahqLevelExistenceIssue,
    SigmahqLevelExistenceValidator,
)


def test_validator_SigmahqLevelExistence():
    validator = SigmahqLevelExistenceValidator()
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
    assert validator.validate(detection_rule) == [SigmahqLevelExistenceIssue([detection_rule])]


def test_validator_SigmahqLevelExistence_valid():
    validator = SigmahqLevelExistenceValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    level: low
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqLevel_correlation():
    validator = SigmahqLevelExistenceValidator()
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
    assert validator.validate(correlation_rule) == [SigmahqLevelExistenceIssue([correlation_rule])]


def test_validator_SigmahqLevel_correlation_valid():
    validator = SigmahqLevelExistenceValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    level: high
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
