from sigma.rule import SigmaRule, SigmaLogSource
from sigma.correlations import SigmaCorrelationRule

from sigma.validators.sigmahq.logsource import (
    SigmahqLogsourceUnknownIssue,
    SigmahqLogsourceUnknownValidator,
)


def test_validator_SigmahqLogsourceKnown():
    validator = SigmahqLogsourceUnknownValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
            space name: 'error'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqLogsourceUnknownIssue([detection_rule], SigmaLogSource(category="test"))
    ]


def test_validator_SigmahqLogsourceKnown_valid():
    validator = SigmahqLogsourceUnknownValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
       product: windows
       service: terminalservices-localsessionmanager
    detection:
        sel:
            field: path\\*something
            space name: 'error'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqLogsourceKnown_valid_correlation_rule():
    validator = SigmahqLogsourceUnknownValidator()
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
