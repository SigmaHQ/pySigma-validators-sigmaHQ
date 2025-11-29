# tests/sigmahq/metadata/test_sigmahq_modified_without_date_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.metadata import (
    SigmahqModifiedWithoutDateIssue,
    SigmahqModifiedWithoutDateValidator,
)


def test_validator_SigmahqModifiedWithoutDate():
    validator = SigmahqModifiedWithoutDateValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    modified: 2023-01-01
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqModifiedWithoutDateIssue([rule])]


def test_validator_SigmahqModifiedWithoutDate_valid():
    validator = SigmahqModifiedWithoutDateValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    date: 2022-01-01
    modified: 2023-01-01
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


# Correlation Rule Tests
def test_validator_SigmahqModifiedWithoutDate_correlation():
    validator = SigmahqModifiedWithoutDateValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    modified: 2023-01-01
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
    assert validator.validate(rule) == [SigmahqModifiedWithoutDateIssue([rule])]


def test_validator_SigmahqModifiedWithoutDate_correlation_valid():
    validator = SigmahqModifiedWithoutDateValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    date: 2022-01-01
    modified: 2023-01-01
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
