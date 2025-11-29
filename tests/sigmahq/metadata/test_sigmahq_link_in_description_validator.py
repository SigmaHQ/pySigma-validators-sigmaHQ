# tests/sigmahq/metadata/test_sigmahq_link_in_description_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.metadata import (
    SigmahqLinkInDescriptionIssue,
    SigmahqLinkInDescriptionValidator,
)


def test_validator_SigmahqLinkInDescription():
    validator = SigmahqLinkInDescriptionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: This is a test with https://example.com link
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqLinkInDescriptionIssue([rule], word="https://")]


def test_validator_SigmahqLinkInDescription_valid():
    validator = SigmahqLinkInDescriptionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: This is a test without link
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
def test_validator_SigmahqLinkInDescription_correlation():
    validator = SigmahqLinkInDescriptionValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    description: This is a test with https://example.com link
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
    assert validator.validate(rule) == [SigmahqLinkInDescriptionIssue([rule], word="https://")]


def test_validator_SigmahqLinkInDescription_correlation_valid():
    validator = SigmahqLinkInDescriptionValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    description: This is a test without link
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
