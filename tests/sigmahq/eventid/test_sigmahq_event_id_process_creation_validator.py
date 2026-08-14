from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.eventid import (
    SigmahqEventIdProcessCreationIssue,
    SigmahqEventIdProcessCreationValidator,
)


def test_validator_SigmahqEventIdProcessCreation_valid():
    validator = SigmahqEventIdProcessCreationValidator()
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


def test_validator_SigmahqEventIdProcessCreation_invalid_security_auditing():
    validator = SigmahqEventIdProcessCreationValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    sel:
        Provider_Name: Microsoft-Windows-Security-Auditing
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqEventIdProcessCreationIssue([rule])]


def test_validator_SigmahqEventIdProcessCreation_invalid_sysmon():
    validator = SigmahqEventIdProcessCreationValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    sel:
        Provider_Name: Microsoft-Windows-Sysmon
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqEventIdProcessCreationIssue([rule])]


def test_validator_SigmahqEventIdProcessCreation_valid_other_provider():
    validator = SigmahqEventIdProcessCreationValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    sel:
        Provider_Name: Other-Provider
    condition: sel
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqEventIdProcessCreation_valid_correlation():
    validator = SigmahqEventIdProcessCreationValidator()
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
