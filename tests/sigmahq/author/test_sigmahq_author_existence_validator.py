from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.author import (
    SigmahqAuthorExistenceIssue,
    SigmahqAuthorExistenceValidator,
)


def test_validator_SigmahqAuthorExistence():
    validator = SigmahqAuthorExistenceValidator()
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
    assert validator.validate(detection_rule) == [SigmahqAuthorExistenceIssue([detection_rule])]


def test_validator_SigmahqAuthorExistence_valid():
    validator = SigmahqAuthorExistenceValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    author: test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqAuthor_correlation():
    validator = SigmahqAuthorExistenceValidator()
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
    assert validator.validate(correlation_rule) == [SigmahqAuthorExistenceIssue([correlation_rule])]


def test_validator_SigmahqAuthor_correlation_valid():
    validator = SigmahqAuthorExistenceValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    author: Test Author
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
