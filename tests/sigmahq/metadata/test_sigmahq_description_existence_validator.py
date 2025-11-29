from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqDescriptionExistenceIssue,
    SigmahqDescriptionExistenceValidator,
)

#
# Detection Rule Tests
#


def test_validator_SigmahqDescriptionExistence():
    validator = SigmahqDescriptionExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqDescriptionExistenceIssue([rule])]


def test_validator_SigmahqDescriptionExistence_valid():
    validator = SigmahqDescriptionExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: a simple description
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


#
# Correlation Rule Tests
#


def test_validator_SigmahqDescription_correlation():
    validator = SigmahqDescriptionExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqDescriptionExistenceIssue([rule])]


def test_validator_SigmahqDescription_correlation_valid():
    validator = SigmahqDescriptionExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    description: This is a test correlation rule
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
