from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.source import (
    SigmahqSourceEventlogIssue,
    SigmahqSourceEventlogValidator,
)


def test_validator_SigmahqSourceEventlog_valid():
    validator = SigmahqSourceEventlogValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    sel:
        field: path
    condition: sel
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqSourceEventlog_invalid():
    validator = SigmahqSourceEventlogValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    sel:
        source: Eventlog
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqSourceEventlogIssue([rule])]


def test_validator_SigmahqSourceEventlog_invalid_lowercase():
    validator = SigmahqSourceEventlogValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    sel:
        source: eventlog
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqSourceEventlogIssue([rule])]


def test_validator_SigmahqSourceEventlog_valid_correlation():
    validator = SigmahqSourceEventlogValidator()
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
