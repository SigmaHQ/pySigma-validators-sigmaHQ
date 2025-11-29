from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.metadata import (
    SigmahqLevelExistenceIssue,
    SigmahqLevelExistenceValidator,
)


#
# Detection Rule Tests
#
def test_validator_SigmahqLevelExistence():
    validator = SigmahqLevelExistenceValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqLevelExistenceIssue([rule])]


def test_validator_SigmahqLevelExistence_valid():
    validator = SigmahqLevelExistenceValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []


#
# Correlation Rule Tests
#


# Tests for Level Existence
def test_validator_SigmahqLevel_correlation():
    validator = SigmahqLevelExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqLevelExistenceIssue([rule])]


def test_validator_SigmahqLevel_correlation_valid():
    validator = SigmahqLevelExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(rule) == []
