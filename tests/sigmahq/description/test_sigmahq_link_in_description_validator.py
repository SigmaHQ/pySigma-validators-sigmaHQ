from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.description import (
    SigmahqLinkInDescriptionIssue,
    SigmahqLinkInDescriptionValidator,
)


def test_validator_SigmahqLinkInDescription():
    validator = SigmahqLinkInDescriptionValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [
        SigmahqLinkInDescriptionIssue([detection_rule], word="https://")
    ]


def test_validator_SigmahqLinkInDescription_valid():
    validator = SigmahqLinkInDescriptionValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqLinkInDescription_correlation():
    validator = SigmahqLinkInDescriptionValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(correlation_rule) == [
        SigmahqLinkInDescriptionIssue([correlation_rule], word="https://")
    ]


def test_validator_SigmahqLinkInDescription_correlation_valid():
    validator = SigmahqLinkInDescriptionValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(correlation_rule) == []
