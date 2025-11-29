# tests/sigmahq/metadata/test_sigmahq_fields_existence_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.metadata import (
    SigmahqFieldsExistenceIssue,
    SigmahqFieldsExistenceValidator,
)


def test_validator_SigmahqFieldsExistence():
    validator = SigmahqFieldsExistenceValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldsExistence_valid():
    validator = SigmahqFieldsExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    fields:
        - field1
        - field2
    """
    )
    assert validator.validate(rule) == [SigmahqFieldsExistenceIssue([rule])]


# Correlation Rule Tests
def test_validator_SigmahqFieldsExistence_correlation():
    validator = SigmahqFieldsExistenceValidator()
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
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldsExistence_correlation_valid():
    validator = SigmahqFieldsExistenceValidator()
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
    fields:
        - field1
        - field2
    """
    )
    assert validator.validate(rule) == [SigmahqFieldsExistenceIssue([rule])]
